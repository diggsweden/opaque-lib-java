// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.BlindedElement;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxEncoder;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Default Implementation of OPRF for Opaque.
 */

public class DefaultOprfFunction extends AbstractOprfFunction {



  /**
   * Constructor, using a curve specified by {@link ECNamedCurveParameterSpec}.
   *
   * @param opaqueCurve curve parameter spec and functions.
   * @param hashFunctions hash functions.
   * @param applicationContext Application context parameter
   */
  public DefaultOprfFunction(OpaqueCurve opaqueCurve, HashFunctions hashFunctions,
      String applicationContext) {
    super(opaqueCurve, hashFunctions, applicationContext);
  }

  @Override
  public BlindedElement blind(byte[] elementData) throws DeriveKeyPairErrorException {
    BigInteger blind = opaqueCurve.randomScalar();
    ECPoint inputElementPoint = opaqueCurve.hashToGroup(elementData);
    if (opaqueCurve.getParameterSpec().getCurve().getInfinity().equals(inputElementPoint)) {
      throw new DeriveKeyPairErrorException("Illegal blind point");
    }
    ECPoint blindedElement = inputElementPoint.multiply(blind);

    return new BlindedElement(blind.toByteArray(), blindedElement);
  }

  @Override
  public byte[] finalize(byte[] elementData, byte[] blind, ECPoint evaluatedElement)
      throws DeserializationException, InvalidInputException {
    BigInteger blindScalar = new BigInteger(1, blind);
    BigInteger blindInverse =
        blindScalar.modInverse(opaqueCurve.getParameterSpec().getCurve().getOrder());
    ECPoint unblindedElement = evaluatedElement.multiply(blindInverse);
    return hashFunctions.hash(new TLSSyntaxEncoder()
        .addVariableLengthData(elementData, 2)
        .addVariableLengthData(unblindedElement.getEncoded(true), 2)
        .addFixedLengthData("Finalize".getBytes(StandardCharsets.UTF_8))
        .toBytes());
  }

  @Override
  public ECPoint blindEvaluate(OprfPrivateKey k, ECPoint blindElement)
      throws DeriveKeyPairErrorException {
    if (k.isByteValue()) {
      ECPoint blindEvaluatePoint = blindElement.multiply(new BigInteger(1, k.getPrivateKeyBytes()));
      return blindEvaluatePoint;
    }
    try {
      byte[] sharedSecretPoint = diffieHellman(k.getKeyPair(), serializeElement(blindElement));
      return deserializeElement(sharedSecretPoint);
    } catch (DeserializationException | NoSuchAlgorithmException | InvalidKeySpecException
        | InvalidKeyException | NoSuchProviderException | InvalidInputException e) {
      throw new DeriveKeyPairErrorException("Error doing blind evaluate with Diffie-Hellman", e);
    }
  }


  @Override
  public KeyPairRecord deriveKeyPair(byte[] seed, String info) throws DeriveKeyPairErrorException {
    try {
      byte[] deriveInput = new TLSSyntaxEncoder()
          .addFixedLengthData(seed)
          .addVariableLengthData(info.getBytes(StandardCharsets.UTF_8), 2)
          .toBytes();
      int counter = 0;
      BigInteger skS = BigInteger.ZERO;
      while (skS.equals(BigInteger.ZERO)) {
        if (counter > 255) {
          throw new DeriveKeyPairErrorException(
              "Key generator counter exceeded max allowed iterations");
        }
        skS = opaqueCurve.hashToScalar(new TLSSyntaxEncoder()
            .addFixedLengthData(deriveInput)
            .addFixedLengthData(OpaqueUtils.i2osp(counter, 1))
            .toBytes(), "DeriveKeyPair");
        counter++;
      }
      ECPoint pkS = opaqueCurve.getParameterSpec().getG().multiply(skS).normalize();
      return new KeyPairRecord(pkS.getEncoded(true), skS.toByteArray());
    } catch (InvalidInputException e) {
      throw new DeriveKeyPairErrorException("Failed to derive deterministic key from seed and info",
          e);
    }
  }


  @Override
  public byte[] diffieHellman(OprfPrivateKey oprfPrivateKey, byte[] publicPoint)
      throws DeserializationException, InvalidInputException {
    if (!oprfPrivateKey.isByteValue()) {
      try {
        return diffieHellman(oprfPrivateKey.getKeyPair(), publicPoint);
      } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException
          | NoSuchProviderException e) {
        throw new InvalidInputException("Invalid DH key agreement parameters", e);
      }
    }
    byte[] privateKey = oprfPrivateKey.getPrivateKeyBytes();
    BigInteger privateScalar = new BigInteger(1, privateKey);
    ECPoint resultPoint = deserializeElement(publicPoint).multiply(privateScalar);
    return opaqueCurve.serializeElement(resultPoint);
  }

  protected byte[] diffieHellman(KeyPair keyPair, byte[] publicPoint)
      throws DeserializationException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidKeyException,
      NoSuchProviderException, InvalidInputException {
    ECPoint ecPoint = deserializeElement(publicPoint);
    // Evaluate PW Point with DiffieHellman
    byte[] sharedSecret = deriveDiffieHellmanSharedSecret(keyPair.getPrivate(), ecPoint);
    byte[] controlPoint = deriveDiffieHellmanSharedSecret(keyPair.getPrivate(),
        ecPoint.add(opaqueCurve.getParameterSpec().getG()));
    byte[] y = deriveYCoordinate(sharedSecret, controlPoint,
        deserializeElement(serializePublicKey(keyPair.getPublic())));
    ECPoint resultPoint = deserializeElement(Arrays.concatenate(y, sharedSecret));
    return serializeElement(resultPoint);
  }

  public byte[] deriveDiffieHellmanSharedSecret(PrivateKey privateKey, ECPoint publicPoint)
      throws DeserializationException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchProviderException,
      InvalidKeySpecException {
    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
    keyAgreement.init(privateKey);
    keyAgreement.doPhase(getPublicECKey(serializeElement(publicPoint)), true);
    return keyAgreement.generateSecret();
  }

}
