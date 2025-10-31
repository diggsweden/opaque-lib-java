// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Test TLS Syntax processing
 */
@Slf4j
class TLSSyntaxTest {


  @Test
  void encodeDataTest() throws Exception {

    TLSSyntaxEncoder encoder = new TLSSyntaxEncoder()
        .addFixedLengthData(Hex.decode("01 02 03 04"))
        .addVariableLengthData(Hex.decode("e1 e2 e3 e4"), 2);

    log.info("Encoded result: {}", Hex.toHexString(encoder.toBytes()));
    assertEquals("010203040004e1e2e3e4", Hex.toHexString(encoder.toBytes()));

    InvalidInputException invalidInputException = assertThrows(InvalidInputException.class, () -> {
      new TLSSyntaxEncoder().addVariableLengthData(
          repeat((byte) 0x7f, 257), 1);
    });
    log.info("Received expected exception: {}", invalidInputException.toString());
  }

  @Test
  void parseDataTest() throws Exception {

    log.info("Testing parser with input hex: 010203040004e1e2e3e4");
    TLSSyntaxParser parser = new TLSSyntaxParser(Hex.decode("010203040004e1e2e3e4"));

    byte[] fixedLengthData = parser.extractFixedLength(4);
    assertEquals("01020304", Hex.toHexString(fixedLengthData));
    log.info("Extracted fixed length data: {}", Hex.toHexString(fixedLengthData));

    assertEquals(6, parser.getData().length);

    byte[] variableLengthData = parser.extractVariableLength(2);
    assertEquals("e1e2e3e4", Hex.toHexString(variableLengthData));
    log.info("Extracted variable length data: {}", Hex.toHexString(variableLengthData));

    assertEquals(0, parser.getData().length);

    byte[] singleValueExtract =
        new TLSSyntaxParser(Hex.decode("04e1e2e3e4")).extractVariableLength(1);
    assertEquals("e1e2e3e4", Hex.toHexString(singleValueExtract));
    log.info("Single value extract: {}", Hex.toHexString(singleValueExtract));


    InvalidInputException invalidInputException = assertThrows(InvalidInputException.class, () -> {
      new TLSSyntaxParser(Hex.decode("04e1e2e3e4")).extractVariableLength(2);
    });
    log.info("Caught expected exception: {}", invalidInputException.toString());

  }

  private byte[] repeat(byte val, int len) {
    byte[] result = new byte[len];
    Arrays.fill(result, val);
    return result;
  }

}
