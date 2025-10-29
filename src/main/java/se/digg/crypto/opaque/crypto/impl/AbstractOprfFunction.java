// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Optional;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Abstract key exchange functions
 */
public abstract class AbstractOprfFunction implements OprfFunctions {

  protected final static byte[] EVEN_Y = new byte[]{0x02};
  protected final static byte[] ODD_Y = new byte[]{0x03};

  protected final String applicationContext;

  protected final HashFunctions hashFunctions;

  protected final OpaqueCurve opaqueCurve;

  /**
   * Constructor, using a curve specified by {@link ECNamedCurveParameterSpec}
   *
   * @param opaqueCurve curve parameter spec and functions
   * @param hashFunctions hash functions
   * @param applicationContext Application context parameter
   */
  public AbstractOprfFunction(OpaqueCurve opaqueCurve, HashFunctions hashFunctions, String applicationContext) {
    this.hashFunctions = hashFunctions;
    this.applicationContext = Optional.ofNullable(applicationContext).orElse("");
    this.opaqueCurve = opaqueCurve;
  }

  /** {@inheritDoc} */
  @Override public KeyPairRecord deriveDiffieHellmanKeyPair(byte[] seed) throws DeriveKeyPairErrorException {
    return deriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair");
  }

  @Override public byte[] getContext() {
    return this.applicationContext.getBytes(StandardCharsets.UTF_8);
  }

  @Override public KeyPair getKeyPair(KeyPairRecord keyPairRecord)
    throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, DeserializationException {
    return new KeyPair(getPublicECKey(keyPairRecord.publicKey()), getPrivateECKey(keyPairRecord.privateKey()));
  }

  @Override public byte[] serializeElement(ECPoint element) {
    return opaqueCurve.serializeElement(element);
  }

  @Override public int getOPRFSerializationSize() {
    return opaqueCurve.getElementSerializationSize();
  }

  @Override public ECPoint deserializeElement(byte[] elementBytes) throws DeserializationException {
    return opaqueCurve.deserializeElement(elementBytes);
  }

  @Override public byte[] serializePublicKey(PublicKey publicKey) {
    try{
      KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
      ECPublicKey bcECPublicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
      return bcECPublicKey.getQ().getEncoded(true);
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  @Override public int getOprfPrivateKeySize() {
    return opaqueCurve.getScalarSize();
  }

  protected byte[] deriveYCoordinate(byte[] sharedSecret, byte[] controlX, PublicKey publicKey)
    throws DeserializationException, InvalidInputException {
    return deriveYCoordinate(sharedSecret, controlX, deserializeElement(serializePublicKey(publicKey)));
  }
  protected byte[] deriveYCoordinate(byte[] sharedSecret, byte[] controlX, ECPoint publicKey)
    throws InvalidInputException, DeserializationException {

    ECPoint evenSecret = deserializeElement(Arrays.concatenate(EVEN_Y, sharedSecret));
    ECPoint oddSecret = deserializeElement(Arrays.concatenate(ODD_Y, sharedSecret));
    byte[] evenSecretPlusPK = getCurve().getSharedSecret(evenSecret.add(publicKey));
    byte[] oddSecretPlusPK = getCurve().getSharedSecret(oddSecret.add(publicKey));

    if (Arrays.areEqual(evenSecretPlusPK, controlX)){
      return EVEN_Y;
    }
    if (Arrays.areEqual(oddSecretPlusPK, controlX)){
      return ODD_Y;
    }
    throw new InvalidInputException("Illegal DH point data");
  }

  @Override public PrivateKey getPrivateECKey(byte[] privateKeyBytes)
    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    return OpaqueUtils.getPrivateECKey(privateKeyBytes, opaqueCurve.getParameterSpec());
  }

  @Override public PublicKey getPublicECKey(byte[] publicKeyBytes)
    throws DeserializationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    return OpaqueUtils.getPublicECKey(publicKeyBytes, opaqueCurve.getParameterSpec());
  }

  @Override public OpaqueCurve getCurve() {
    return opaqueCurve;
  }

}
