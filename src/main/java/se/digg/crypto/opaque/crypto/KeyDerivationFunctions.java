package se.digg.crypto.opaque.crypto;

import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.keys.DerivedKeys;

/**
 * Key derivation functions interface
 */
public interface KeyDerivationFunctions {

  /**
   * Extract a pseudorandom key of fixed length Nx bytes from input keying material ikm and an optional byte string salt.
   *
   * @param salt salt value
   * @param inputKeyingMaterial input keying material
   * @return an extracted pseudorandom key
   */
  byte[] extract(byte[] salt, byte[] inputKeyingMaterial);

  /**
   * Getter for the size of extracted keys (Nx)
   *
   * @return the size of extracted keys
   */
  int getExtractSize();

  /**
   * The size of nonce values (Nn) used in Opaque key derivation. For regular usage in Opaque Nn = Nseed = 32
   *
   * @return nonce value size
   */
  int getNonceSize();

  /**
   * Sizes of random nonce and seeds. When used in Opaque, these values should always be set to
   * Nseed = Nn = 32
   *
   * @return
   */
  int getSeedSize();

  /**
   * Expands a pseudorandom key using the optional info element into l bytes of keying material
   *
   * @param pseudoRandomKey pseudorandom key
   * @param info optional info parameter
   * @param l length of output
   * @return keying material of length l
   */
  byte[] expand(byte[] pseudoRandomKey, String info, int l);
  byte[] expand(byte[] pseudoRandomKey, byte[] info, int l);

  /**
   * Derive-Secret(Secret, Label, Transcript-Hash) = Expand-Label(Secret, Label, Transcript-Hash, Nx)
   * Expand-Label(Secret, Label, Context, Length) = Expand(Secret, CustomLabel, Length)
   *
   * @param ikm inputKeyingMaterial
   * @param preamble seed data
   * @return derived key
   * @throws InvalidInputException invalid key derivation data
   */
  DerivedKeys deriveKeys(byte[] ikm, byte[] preamble) throws InvalidInputException;


}
