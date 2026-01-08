// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.hash2curve.HashToCurveProfile;
import org.bouncycastle.crypto.hash2curve.HashToEllipticCurve;
import org.bouncycastle.crypto.hash2curve.OPRFHashToScalar;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.OpaqueCurve;

/**
 * Default OPAQUE curve implementing hash2curve from RFC 9380.
 */

public class DefaultOpaqueCurve implements OpaqueCurve {

  protected static final SecureRandom RNG = new SecureRandom();

  protected final ECParameterSpec parameterSpec;
  protected final HashToEllipticCurve h2c;
  protected final OPRFHashToScalar hashToScalar;

  protected final DstContext dst;

  protected final int privateKeySerializationSize;
  protected final int publicKeySerializationSize;

  public DefaultOpaqueCurve(ECParameterSpec parameterSpec, HashToCurveProfile hashToCurveProfile,
      DstContext dst) {
    this.parameterSpec = parameterSpec;
    this.publicKeySerializationSize = serializeElement(parameterSpec.getG()).length;
    int bitLen = parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE).bitLength();
    this.privateKeySerializationSize = (int) Math.ceil((double) bitLen / 8);
    this.dst = dst;

    Digest digest = switch (hashToCurveProfile) {
      case P256_XMD_SHA_256 -> new SHA256Digest();
      case P384_XMD_SHA_384 -> new SHA384Digest();
      case P521_XMD_SHA_512 -> new SHA512Digest();
      case CURVE25519W_XMD_SHA_512_ELL2 -> new SHA512Digest();
      default -> throw new IllegalArgumentException("Unsupported has to curve profile");
    };

    this.h2c = HashToEllipticCurve.getInstance(hashToCurveProfile,
        new String(dst.getHash2CurveDST(), StandardCharsets.UTF_8));
    this.hashToScalar = new OPRFHashToScalar(parameterSpec.getCurve(), digest,
        hashToCurveProfile.getK());
  }

  @Override
  public ECParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  @Override
  public BigInteger hashToScalar(byte[] seed) {
    return hashToScalar.process(seed, dst.getHash2ScalarDefaultDST());
  }

  @Override
  public BigInteger hashToScalar(byte[] seed, String domain) {
    return hashToScalar.process(seed, dst.getDomainSeparationTag(domain));
  }

  @Override
  public ECPoint hashToGroup(byte[] seed) {
    return h2c.hashToCurve(seed);
  }

  @Override
  public BigInteger randomScalar() {
    return hashToScalar(OpaqueUtils.random(getScalarSize()));
  }

  @Override
  public byte[] serializeElement(ECPoint ecPoint) {
    return ecPoint.getEncoded(true);
  }

  @Override
  public int getElementSerializationSize() {
    return publicKeySerializationSize;
  }

  @Override
  public ECPoint deserializeElement(byte[] elementBytes) {
    return parameterSpec.getCurve().decodePoint(elementBytes);
  }

  @Override
  public int getScalarSize() {
    return privateKeySerializationSize;
  }

  @Override
  public byte[] getSharedSecret(ECPoint point) {
    byte[] secret = serializeElement(point);
    return Arrays.copyOfRange(secret, 1, secret.length);
  }
}
