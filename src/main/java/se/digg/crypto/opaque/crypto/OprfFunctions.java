// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.opaque.client.BlindedElement;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Interface for providing an OPRF implementation.
 */

public interface OprfFunctions {

  /**
   * Create and output (blind, blinded_element), consisting of a blinded representation of an input
   * element, denoted blinded_element, along with a value to revert the blinding process, denoted
   * blind.
   *
   * @param elementData the element data to blind
   * @return the blinded element
   * @throws DeriveKeyPairErrorException if key derivation fails
   */
  BlindedElement blind(byte[] elementData) throws DeriveKeyPairErrorException;

  /**
   * Finalize the OPRF evaluation using input element, random inverter blind, and evaluation output
   * evaluated_element, yielding output oprf_output.
   *
   * @param elementData input element.
   * @param blind blind element.
   * @param evaluatedElement evaluated element.
   * @return finalized OPRF data.
   * @throws DeserializationException error deserializing data.
   * @throws InvalidInputException invalid input error
   */
  byte[] finalize(byte[] elementData, byte[] blind, ECPoint evaluatedElement)
      throws DeserializationException, InvalidInputException;

  /**
   * Evaluate blinded input element blinded_element using input key k, yielding output element
   * evaluated_element. This is equivalent to the BlindEvaluate function described in [OPRF],
   * Section 3.3.1, where k is the private key parameter.
   *
   * @param k key.
   * @param blindElement blind element.
   * @return blind evaluate element.
   * @throws DeriveKeyPairErrorException error deriving key pair
   */
  ECPoint blindEvaluate(OprfPrivateKey k, ECPoint blindElement) throws DeriveKeyPairErrorException;

  /**
   * Serializes an ECPoint element to bytes.
   *
   * @param element EC point.
   * @return bytes of serialized point
   */
  byte[] serializeElement(ECPoint element);

  /**
   * Getter for OPRF serialization Size. This is this serialized size of EC point elements.
   *
   * @return EC point element serialization size
   */
  int getOPRFSerializationSize();

  /**
   * Deserialize an element from byte array to an EC point element.
   *
   * @param elementBytes bytes of the element.
   * @return EC point element.
   * @throws DeserializationException error deserializing data
   */
  ECPoint deserializeElement(byte[] elementBytes) throws DeserializationException;

  /**
   * Serialize an EC point in the form of a public key element.
   *
   * @param publicKey public key element.
   * @return serialized public key
   */
  byte[] serializePublicKey(PublicKey publicKey);

  /**
   * Getter for the size of a private key in byte array format.
   *
   * @return size of a private key provided as a byte array
   */
  int getOprfPrivateKeySize();

  /**
   * Derive a Diffie-Hellman key pair.
   *
   * @param seed key derivation seed.
   * @return key pair.
   * @throws DeriveKeyPairErrorException error deriving key pair
   */
  KeyPairRecord deriveDiffieHellmanKeyPair(byte[] seed) throws DeriveKeyPairErrorException;

  /**
   * Derive a public private key pair.
   *
   * @param seed key derivation seed.
   * @param info optional info parameter.
   * @return key pair.
   * @throws DeriveKeyPairErrorException error deriving key pair
   */
  KeyPairRecord deriveKeyPair(byte[] seed, String info) throws DeriveKeyPairErrorException;

  /**
   * Perform a Diffie-Hellman operation to derive a shared secret.
   *
   * @param privateKey private key scalar bytes.
   * @param publicKey public key bytes.
   * @return x-coordinate of result point expressed as a byte array.
   * @throws DeserializationException error deserializing data
   */
  byte[] diffieHellman(OprfPrivateKey privateKey, byte[] publicKey)
      throws DeserializationException, InvalidInputException;

  /**
   * Get the registered context for this OPRF function.
   *
   * @return context string as byte array
   */
  byte[] getContext();

  /**
   * Convert {@link KeyPairRecord} to {@link KeyPair}.
   *
   * @param keyPairRecord key pair record.
   * @return {@link KeyPair}.
   * @throws NoSuchAlgorithmException error converting key types.
   * @throws InvalidKeySpecException error converting key types.
   * @throws NoSuchProviderException error converting key types.
   * @throws DeserializationException error converting key types
   */
  KeyPair getKeyPair(KeyPairRecord keyPairRecord)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
      DeserializationException;

  OpaqueCurve getCurve();

  PrivateKey getPrivateECKey(byte[] privateKeyBytes)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException;


  PublicKey getPublicECKey(byte[] publicKeyBytes)
      throws DeserializationException, NoSuchAlgorithmException, NoSuchProviderException,
      InvalidKeySpecException;

}
