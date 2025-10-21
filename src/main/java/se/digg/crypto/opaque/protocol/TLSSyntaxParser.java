// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.protocol;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

import lombok.Getter;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Parsing byte data formatted using the TLS syntax
 */
public class TLSSyntaxParser {

  @Getter private byte[] data;

  /**
   * Creates a syntax parser setup with data to be parsed
   *
   * @param data data to be parsed
   */
  public TLSSyntaxParser(byte[] data) {
    this.data = data;
  }

  /**
   * Extract fixed length data
   *
   * @param len fixed length size
   * @return extracted data
   * @throws InvalidInputException if length exceeds available data
   */
  public byte[] extractFixedLength(int len) throws InvalidInputException {
    byte[] extract = Arrays.copyOf(data, len);
    data = reduceData(len);
    return extract;
  }

  /**
   * Extract variable length byte data
   *
   * @param lengthParamBytes number of bytes of the length tag
   * @return extracted data according to length tag
   * @throws InvalidInputException if length tag indicates data length that exceeds available data
   */
  public byte[] extractVariableLength(int lengthParamBytes) throws InvalidInputException {
    if (lengthParamBytes > 4) {
      throw new IllegalArgumentException("Length byte larger than 4 bytes is not allowed");
    }
    int extractLen = new BigInteger(
      // Make sure that a positive value is collected by adding a leading 00 byte
      Arrays.concatenate(new byte[]{0x00}, Arrays.copyOf(data, lengthParamBytes))).intValue();
    data = reduceData(lengthParamBytes);
    return extractFixedLength(extractLen);
  }

  private byte[] reduceData(int len) throws InvalidInputException {
    if (len > data.length) {
      throw new InvalidInputException("Length exceeds the available data");
    }
    return Arrays.copyOfRange(data, len, data.length);
  }





}
