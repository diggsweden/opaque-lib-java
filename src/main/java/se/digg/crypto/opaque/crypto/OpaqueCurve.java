// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Interface for specific functions and properties bound to a particular selected EC curve.
 */

public interface OpaqueCurve {

  ECParameterSpec getParameterSpec();

  BigInteger hashToScalar(byte[] seed);

  BigInteger hashToScalar(byte[] seed, String domain);

  ECPoint hashToGroup(byte[] seed);

  BigInteger randomScalar();

  byte[] serializeElement(ECPoint ecPoint);

  int getElementSerializationSize();

  ECPoint deserializeElement(byte[] elementBytes);

  int getScalarSize();

  byte[] getSharedSecret(ECPoint point);

}
