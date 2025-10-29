// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import se.digg.crypto.hashtocurve.CurveProcessor;
import se.digg.crypto.hashtocurve.HashToEllipticCurve;
import se.digg.crypto.hashtocurve.HashToScalar;
import se.digg.crypto.hashtocurve.MapToCurve;
import se.digg.crypto.hashtocurve.MessageExpansion;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.hashtocurve.impl.GenericCurveProcessor;
import se.digg.crypto.hashtocurve.impl.GenericHashToField;
import se.digg.crypto.hashtocurve.impl.GenericOPRFHashToScalar;
import se.digg.crypto.hashtocurve.impl.ShallueVanDeWoestijneMapToCurve;
import se.digg.crypto.hashtocurve.impl.XmdMessageExpansion;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.OpaqueCurve;

/**
 * Default OPAQUE curve implementing hash2curve from RFC 9380
 */
public class DefaultOpaqueCurve implements OpaqueCurve {

  protected final static SecureRandom RNG = new SecureRandom();

  protected final ECParameterSpec parameterSpec;
  protected final HashToEllipticCurve h2c;
  protected final HashToScalar hashToScalar;

  protected final DstContext dst;

  protected final int privateKeySerializationSize;
  protected final int publicKeySerializationSize;

  public DefaultOpaqueCurve(ECParameterSpec parameterSpec, HashToCurveProfile hashToCurveProfile, DstContext dst) {
    this.parameterSpec = parameterSpec;
    this.publicKeySerializationSize = serializeElement(parameterSpec.getG()).length;
    int bitLen = parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE).bitLength();
    this.privateKeySerializationSize = (int) Math.ceil((double) bitLen / 8);
    this.dst = dst;

    ECParameterSpec spec = switch (hashToCurveProfile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-256");
      case P384_XMD_SHA_384_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-384");
      case P521_XMD_SHA_512_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-521");
      case curve25519_XMD_SHA_512_ELL2_RO_ -> ECNamedCurveTable.getParameterSpec("curve25519");
      default -> throw new IllegalArgumentException("Unsupported has to curve profile");
    };
    Digest digest = switch (hashToCurveProfile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> new SHA256Digest();
      case P384_XMD_SHA_384_SSWU_RO_ -> new SHA384Digest();
      case P521_XMD_SHA_512_SSWU_RO_ -> new SHA512Digest();
      case curve25519_XMD_SHA_512_ELL2_RO_ -> new SHA512Digest();
      default -> throw new IllegalArgumentException("Unsupported has to curve profile");
    };

    CurveProcessor curveProcessor = new GenericCurveProcessor(spec);
    MessageExpansion messExp = new XmdMessageExpansion(digest, hashToCurveProfile.getK());
    GenericHashToField hashToField = new GenericHashToField(dst.getHash2CurveDST(), spec, messExp, hashToCurveProfile.getL());
    MapToCurve mapToCurve = new ShallueVanDeWoestijneMapToCurve(spec, hashToCurveProfile.getZ());
    this.h2c = new HashToEllipticCurve(hashToField, mapToCurve, curveProcessor);
    this.hashToScalar = new GenericOPRFHashToScalar(parameterSpec, digest, hashToCurveProfile.getK());
  }

  @Override public ECParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  @Override public BigInteger hashToScalar(byte[] seed) {
    return hashToScalar.process(seed, dst.getHash2ScalarDefaultDST());
  }

  @Override public BigInteger hashToScalar(byte[] seed, String domain) {
    return hashToScalar.process(seed, dst.getDomainSeparationTag(domain));
  }

  @Override public ECPoint hashToGroup(byte[] seed) {
    return h2c.hashToEllipticCurve(seed);
  }

  @Override public BigInteger randomScalar() {
    return hashToScalar(OpaqueUtils.random(getScalarSize()));
  }

  @Override public byte[] serializeElement(ECPoint ecPoint) {
    return ecPoint.getEncoded(true);
  }

  @Override public int getElementSerializationSize() {
    return publicKeySerializationSize;
  }

  @Override public ECPoint deserializeElement(byte[] elementBytes) {
    return parameterSpec.getCurve().decodePoint(elementBytes);
  }

  @Override public int getScalarSize() {
    return privateKeySerializationSize;
  }

  @Override public byte[] getSharedSecret(ECPoint point) {
    byte[] secret = serializeElement(point);
    return Arrays.copyOfRange(secret, 1, secret.length);
  }
}
