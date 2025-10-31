// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import java.math.BigInteger;
import java.security.SecureRandom;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;

/**
 * Implements a generic implementation of OpaqueCurve with simplified generation of G.hashToGroup.
 *
 * <p>
 * This simplified implementation is safe from exposing a known discrete log relationship with the
 * generated point.
 *
 * <p>
 * This implementation makes a reasonable effort to produce a result in constant ime regardless of
 * how many attempts that are needed to find a valid EC point.
 */

@Slf4j
public class SimplifiedOpaqueCurve implements OpaqueCurve {

  protected static final SecureRandom RNG = new SecureRandom();
  protected static final String invalidPoint =
      "022874574724f40d0e5f7aa9f70b8f4b01ed7521033d75676d9584c2de33dd9591";
  protected static final String validPoint =
      "03c3be0fce9bad38dc3978517f4f74442901d3dc22502af2f9be3dba026b322b66";

  protected final ECParameterSpec parameterSpec;
  protected final HashFunctions hashFunctions;

  protected final int privateKeySerializationSize;
  protected final int publicKeySerializationSize;

  protected final int constantIterations;

  @Setter
  private boolean devMode = false;

  /**
   * Constructor using a dafault value of 6 ms minimum constant time.
   *
   * @param parameterSpec parameter spec.
   * @param hashFunctions hash functions
   */
  public SimplifiedOpaqueCurve(ECParameterSpec parameterSpec, HashFunctions hashFunctions) {
    this(parameterSpec, hashFunctions, 64);
  }

  /**
   * Constructor.
   *
   * @param parameterSpec parameter spec.
   * @param hashFunctions hash functions.
   * @param constantIterations number of iterations allways done to find a point
   */
  public SimplifiedOpaqueCurve(ECParameterSpec parameterSpec, HashFunctions hashFunctions,
      int constantIterations) {
    this.parameterSpec = parameterSpec;
    this.hashFunctions = hashFunctions;
    this.publicKeySerializationSize = serializeElement(parameterSpec.getG()).length;
    int bitLen = parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE).bitLength();
    this.privateKeySerializationSize = (int) Math.ceil((double) bitLen / 8);
    this.constantIterations = constantIterations;
  }

  @Override
  public ECParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  @Override
  public BigInteger hashToScalar(byte[] seed) {
    return new BigInteger(1, hashFunctions.hash(seed)).mod(
        parameterSpec.getCurve().getOrder());
  }

  @Override
  public BigInteger hashToScalar(byte[] seed, String domain) {
    return hashToScalar(seed);
  }

  @Override
  public ECPoint hashToGroup(byte[] seed) {
    ECPoint result = null;
    // ECPoint temp;
    int successAttempt = -1;
    int failedAttempts = 0;
    int successAttempts = 0;
    for (int count = 0; count < constantIterations; count++) {
      ECPoint ecPoint = hashToEcPointAttempt(seed, count);
      if (result == null) {
        if (ecPoint != null) {
          successAttempt = count;
          result = ecPoint;
          successAttempts++;
        } else {
          // temp =
          parameterSpec.getG();
          failedAttempts++;
        }
      } else {
        if (ecPoint != null) {
          successAttempt = successAttempt;
          result = result;
          successAttempts++;
        } else {
          // temp =
          parameterSpec.getG();
          failedAttempts++;
        }
      }
    }
    if (result == null) {
      // No result was obtained. Keep running until 128 attempts has failed
      // This option guards against a small iteration counter above
      for (int count = constantIterations; count < 128; count++) {
        ECPoint ecPoint = hashToEcPointAttempt(seed, count);
        if (ecPoint != null) {
          if (log.isDebugEnabled()) {
            log.debug("Found a valid point on the curve after {} attempts", count + 1);
          }
          return ecPoint;
        }
      }
      throw new IllegalStateException("Failed to find a valid point on the curve");
    } else {
      if (log.isDebugEnabled() && devMode) {
        log.debug("Found a valid point on the curve after {} attempts", successAttempt + 1);
        log.debug("Total valid points = {}", successAttempts);
        log.debug("Total invalid points = {}", failedAttempts);
      }
    }
    return result;
  }

  @Override
  public BigInteger randomScalar() {
    return new BigInteger(512, RNG)
        .mod(parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE))
        .add(BigInteger.ONE);
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

  byte[] hkdf(byte[] seed, byte[] info) {
    Digest digest = new SHA256Digest();
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
    hkdf.init(new HKDFParameters(seed, null, info));
    byte[] out = new byte[publicKeySerializationSize];
    hkdf.generateBytes(out, 0, publicKeySerializationSize);
    return out;
  }

  private ECPoint hashToEcPointAttempt(byte[] seed, int count) {
    ECPoint result = null;
    try {
      byte[] yx = hkdf(hashFunctions.hash(seed), OpaqueUtils.i2osp(count, 1));
      byte[] y = yx[0] % 2 == 0 ? new byte[] {0x02} : new byte[] {0x03};
      byte[] x = Arrays.copyOfRange(yx, 1, publicKeySerializationSize);
      result = parameterSpec.getCurve().decodePoint(OpaqueUtils.concat(y, x));
    } catch (Exception ignored) {
      // This was not a valid point on the curve
      parameterSpec.getCurve().decodePoint(Hex.decode(validPoint));
      return null;
    }
    try {
      parameterSpec.getCurve().decodePoint(Hex.decode(invalidPoint));
    } catch (Exception ignored) {
      // This should always be an exception
    }
    return result;
  }

}
