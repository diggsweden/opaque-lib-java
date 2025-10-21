// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.protocol;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

import lombok.Getter;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Encoding data to a byte string using TLS syntax
 */
public class TLSSyntaxEncoder {

  private byte[] data;

  public TLSSyntaxEncoder() {
    this.data = new byte[]{};
  }

  public static TLSSyntaxEncoder getInstance() {
    return new TLSSyntaxEncoder();
  }

  public TLSSyntaxEncoder addFixedLengthData(byte[] newData) {
    this.data = Arrays.concatenate(data, newData);
    return this;
  }

  public TLSSyntaxEncoder addVariableLengthData(byte[] newData, int lengthBytes) throws InvalidInputException {
    byte[] paddedLengthVal = OpaqueUtils.i2osp(newData.length, lengthBytes);
    addFixedLengthData(paddedLengthVal);
    addFixedLengthData(newData);
    return this;
  }

  public byte[] toBytes() {
    return this.data;
  }

}
