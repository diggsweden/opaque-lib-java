// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.testimpl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;

/**
 * Mock generic implementation of an Opaque curve.
 * This implementation does not provide safe functions for hashToScalar, hashToGroup and randomScalar.
 * These implementations are only used for testing purposes.
 */
public class MockGenericOpaqueCurve implements OpaqueCurve {

  protected final static SecureRandom RNG = new SecureRandom();
  protected final ECNamedCurveParameterSpec parameterSpec;
  protected final HashFunctions hashFunctions;

  protected final int privateKeySerializationSize;
  protected final int publicKeySerializationSize;

  public MockGenericOpaqueCurve(ECNamedCurveParameterSpec parameterSpec, HashFunctions hashFunctions) {
    this.parameterSpec = parameterSpec;
    this.hashFunctions = hashFunctions;
    this.publicKeySerializationSize = serializeElement(parameterSpec.getG()).length;
    this.privateKeySerializationSize = parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE).toByteArray().length;
  }

  @Override public ECNamedCurveParameterSpec getParameterSpec() {
    return parameterSpec;
  }

  @Override public BigInteger hashToScalar(byte[] seed) {
    return new BigInteger(1, hashFunctions.hash(seed)).mod(
      parameterSpec.getCurve().getOrder());
  }

  @Override public BigInteger hashToScalar(byte[] seed, String domain) {
    return hashToScalar(seed);
  }

  @Override public ECPoint hashToGroup(byte[] elementData) {
    BigInteger inputScalar = new BigInteger(1, hashFunctions.hash(elementData)).mod(
      parameterSpec.getCurve().getOrder());
    return parameterSpec.getG().multiply(inputScalar);
  }

  @Override public BigInteger randomScalar() {
    return new BigInteger(512, RNG).mod(parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE))
      .add(BigInteger.ONE);
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
