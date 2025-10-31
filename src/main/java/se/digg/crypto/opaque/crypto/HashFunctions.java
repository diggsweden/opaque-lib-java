// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

/**
 * Generic implementation of Hash Functions
 */
public class HashFunctions {

  /** Implementation of the stretch algorithm used in OPRF */
  StretchAlgorithm stretchAlgorithm;
  /** Digest algorithm used as the base hash function */
  Digest digestAlgorithm;

  /**
   * Constructor
   *
   * @param digestAlgorithm digest algorithm used as the base hash function
   * @param stretchAlgorithm the stretch algorithm used in OPRF
   */
  public HashFunctions(Digest digestAlgorithm, StretchAlgorithm stretchAlgorithm) {
    this.stretchAlgorithm = stretchAlgorithm;
    this.digestAlgorithm = digestAlgorithm;
  }

  /**
   * Key stretching is done to help prevent password disclosure in the event of server compromise.
   * Applying a key stretching function to the output of the OPRF greatly increases the cost of an
   * offline attack upon the compromise of the credential file at the server.
   *
   * @param message the data to stretch
   * @return stretched message
   */
  public byte[] stretch(byte[] message) {
    return stretchAlgorithm.stretch(message, getHashSize());
  }

  /**
   * Calculates a hash over a message
   *
   * @param message message
   * @return hash value
   */
  public byte[] hash(byte[] message) {
    Digest digest = getDigestInstance();
    digest.update(message, 0, message.length);
    byte[] hashResult = new byte[getHashSize()];
    digest.doFinal(hashResult, 0);
    return hashResult;
  }

  /**
   * Get an instance of the digest function
   *
   * @return digest instance
   */
  public Digest getDigestInstance() {
    return DigestFactory.cloneDigest(digestAlgorithm);
  }

  /**
   * Gets the size of hash values in bytes
   *
   * @return hash size in bytes
   */
  public int getHashSize() {
    return digestAlgorithm.getDigestSize();
  }

  /**
   * Calculates a MAC (Message Authentication Code) over a message
   *
   * @param key MAC key
   * @param message message
   * @return mac calculated over the message using the input key
   */
  public byte[] mac(byte[] key, byte[] message) {
    HMac hMac = new HMac(getDigestInstance());
    hMac.init(new KeyParameter(key));
    hMac.update(message, 0, message.length);
    byte[] hmacResult = new byte[getMacSize()];
    hMac.doFinal(hmacResult, 0);
    return hmacResult;
  }

  /**
   * Getter for MAC size in bytes
   *
   * @return MAC size in bytes
   */
  public int getMacSize() {
    return getHashSize();
  }
}
