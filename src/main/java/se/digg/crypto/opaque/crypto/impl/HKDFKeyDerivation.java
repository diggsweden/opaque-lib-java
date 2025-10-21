// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import lombok.Setter;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxEncoder;
import se.digg.crypto.opaque.server.keys.DerivedKeys;

/**
 * Key derivation based on HKDF
 */
public class HKDFKeyDerivation implements KeyDerivationFunctions {

  private final HashFunctions hashFunctions;

  /** Size of extracted keying material. For HKDF this is always the size of the hash function used by HKDF */
  @Setter private int extractSize;
  /** Nonce size Nn. For Opaque this should always be 32 */
  @Setter private int nonceSize;
  /** Seed size Nseed. For Opaque this should always be 32 */
  @Setter private int seedSize;

  /**
   * Constructor
   *
   * @param hashFunctions the hash functions used by HKDF
   */
  public HKDFKeyDerivation(HashFunctions hashFunctions) {
    this.hashFunctions = hashFunctions;
    this.extractSize = hashFunctions.getHashSize();
    this.nonceSize = 32;
    this.seedSize = 32;
  }
  /** {@inheritDoc} */
  @Override public byte[] extract(byte[] salt, byte[] inputKeyingMaterial) {
    HKDFBytesGenerator hkdfGenerator = new HKDFBytesGenerator(hashFunctions.getDigestInstance());
    hkdfGenerator.init(HKDFParameters.defaultParameters(inputKeyingMaterial));
    return hkdfGenerator.extractPRK(salt, inputKeyingMaterial);
  }

  /** {@inheritDoc} */
  @Override public byte[] expand(byte[] pseudoRandomKey, String info, int l) {
    return expand(pseudoRandomKey, info.getBytes(StandardCharsets.UTF_8), l);
  }

  /** {@inheritDoc} */
  @Override public byte[] expand(byte[] pseudoRandomKey, byte[] info, int l) {
    HKDFBytesGenerator hkdfGenerator = new HKDFBytesGenerator(new SHA256Digest());
    hkdfGenerator.init(HKDFParameters.skipExtractParameters(pseudoRandomKey, info));
    byte[] expandedKey = new byte[l];
    hkdfGenerator.generateBytes(expandedKey, 0, l);
    return expandedKey;
  }

  /** {@inheritDoc} */
  @Override public DerivedKeys deriveKeys(byte[] ikm, byte[] preamble) throws InvalidInputException {
    byte[] prk = extract(null, ikm);
    int len = getExtractSize();

    byte[] handshakeSecret = expand(
      prk, getCustomLabel("HandshakeSecret", hashFunctions.hash(preamble), len), len);
    byte[] sessionKey = expand(
      prk, getCustomLabel("SessionKey", hashFunctions.hash(preamble), len), len);
    byte[] km2 = expand(handshakeSecret, getCustomLabel("ServerMAC", new byte[]{}, len), len);
    byte[] km3 = expand(handshakeSecret, getCustomLabel("ClientMAC", new byte[]{}, len), len);

    return new DerivedKeys(km2, km3, sessionKey);
  }

  /**
   * <code>
   *  struct {
   *      uint16 length = Length;
   *      opaque label<8..255> = "OPAQUE-" + Label;
   *      uint8 context<0..255> = Context;
   *    } CustomLabel;*
   * </code>
   *
   * @param label label
   * @param context contextData
   * @return custom label
   */
  private byte[] getCustomLabel(String label, byte[] context, int length) throws InvalidInputException {
    byte[] labelBytes = ("OPAQUE-" + label).getBytes(StandardCharsets.UTF_8);
    return TLSSyntaxEncoder.getInstance()
      .addFixedLengthData(OpaqueUtils.i2osp(length, 2))
      .addVariableLengthData(labelBytes, 1)
      .addVariableLengthData(context, 1)
      .toBytes();
  }

  /** {@inheritDoc} */
  @Override public int getExtractSize() {
    return this.extractSize;
  }

  /** {@inheritDoc} */
  @Override public int getNonceSize() {
    return this.nonceSize;
  }

  /** {@inheritDoc} */
  @Override public int getSeedSize() {
    return seedSize;
  }

}
