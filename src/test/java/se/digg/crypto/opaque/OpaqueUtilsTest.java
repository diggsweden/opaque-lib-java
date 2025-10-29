// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.opaque.client.CleartextCredentials;
import se.digg.crypto.opaque.dto.AuthRequest;
import se.digg.crypto.opaque.dto.CredentialRequest;
import se.digg.crypto.opaque.dto.CredentialResponse;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Tests for Opaque utils functions
 */
@Slf4j
class OpaqueUtilsTest {

  @Test
  void concatTest() throws Exception {
    log.info("Concatenating strings");
    String strings = new String(OpaqueUtils.concat("Stringa-", "Stringb-", "Stringc"), StandardCharsets.UTF_8);
    assertEquals("Stringa-Stringb-Stringc", strings);
    log.info("Concatenated Strings: {}", strings);

    byte[] stringByteConcat = OpaqueUtils.concat("ab", Hex.decode("e1 e2 e3"));
    assertEquals("6162e1e2e3", Hex.toHexString(stringByteConcat));
    log.info("String and byte array concatenation: {}", Hex.toHexString(stringByteConcat));

    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
      OpaqueUtils.concat("String", List.of("AnotherString"));
    });
    log.info("Caught exception: {}", exception.toString());
  }

  @Test
  void randomTest() throws Exception {

    byte[] random = OpaqueUtils.random(1024);
    log.info("Created random byte array of len 256: {}", Hex.toHexString(random));
    checkRandomness(random, 18);
    assertEquals(1024, random.length);
  }

  @Test
  void zeroesTest() throws Exception {
    assertEquals("00000000000000000000000000000000", Hex.toHexString(OpaqueUtils.zeroes(16)));
    log.info("Passed zeroes test");
  }

  @Test
  void xorTest() throws Exception {

    /*
     01 82 : 0000 0001 1000 0010
     11 45 : 0001 0001 0100 0101
     --------------------------- XOR
     10 c7 : 0001 0000 1100 0111
    */

    byte[] xor = OpaqueUtils.xor(Hex.decode("01 82"), Hex.decode("11 45"));
    log.info("XOR operation of 01 82 with 11 45 --> {}", Hex.toHexString(xor));
    assertEquals("10c7", Hex.toHexString(xor));

    InvalidInputException invalidInputException = assertThrows(InvalidInputException.class, () -> {
      OpaqueUtils.xor(Hex.decode("01 82"), Hex.decode("11 45 21"));
    });
    log.info("Thrown expected exception: {}", invalidInputException.toString());

  }

  @Test
  void splitTest() throws Exception {

    List<byte[]> split = OpaqueUtils.split(Hex.decode("01 02 03 04 05 06 07 08 09"), 6);
    log.info("Split 1: {}, slit 2: {}", Hex.toHexString(split.get(0)), Hex.toHexString(split.get(1)));
    assertEquals("010203040506",  Hex.toHexString(split.get(0)));
    assertEquals("070809",  Hex.toHexString(split.get(1)));
  }

  @Test
  void i2ospTest() throws Exception {

    log.info("255 as 1 byte: {}", Hex.toHexString(OpaqueUtils.i2osp(255, 1)));
    assertArrayEquals(Hex.decode("ff"), OpaqueUtils.i2osp(255, 1));
    log.info("255 as 2 byte: {}", Hex.toHexString(OpaqueUtils.i2osp(255, 2)));
    assertArrayEquals(Hex.decode("00ff"), OpaqueUtils.i2osp(255, 2));
    log.info("256 as 2 byte: {}", Hex.toHexString(OpaqueUtils.i2osp(256, 2)));
    assertArrayEquals(Hex.decode("0100"), OpaqueUtils.i2osp(256, 2));

    InvalidInputException invalidInputException = assertThrows(InvalidInputException.class, () -> {
      Hex.toHexString(OpaqueUtils.i2osp(256, 1));
    });
    log.info("Caught expected exception: {}", invalidInputException.toString());

  }

  @Test
  void os2ipTest() throws Exception {

    BigInteger ff = OpaqueUtils.os2ip(Hex.decode("ff"));
    log.info("Parsing byte ff to: {}", ff);
    assertEquals(255, ff.intValue());

    BigInteger e0ff = OpaqueUtils.os2ip(Hex.decode("e0ff"));
    log.info("Parsing byte e0ff to: {}", e0ff);
    assertEquals(57599, e0ff.intValue());

    BigInteger longInt = OpaqueUtils.os2ip(Hex.decode("10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff"));
    log.info("Parsing long byte array to: {}", longInt);
    assertEquals("5444517870735015415413993718908291383551", longInt.toString());
  }

  @Test
  void preambleTest() throws Exception {

    byte[] preamble = OpaqueUtils.preamble(
      Hex.decode("01"),
      new KE1(
        new CredentialRequest(Hex.decode("ff")),
        new AuthRequest(
          Hex.decode("23"),
          Hex.decode("77")
        )
      ),
      Hex.decode("55"),
      new CredentialResponse(
        Hex.decode("11"),
        Hex.decode("12"),
        Hex.decode("13")
      ),
      Hex.decode("23"),
      Hex.decode("24"),
      Hex.decode("25")
    );

    log.info("CreatedTestPreamble: {}", Hex.toHexString(preamble) );
    assertEquals("4f504151554576312d000125000101ff23770001551112132324", Hex.toHexString(preamble));
  }

  @Test
  void createCleartextCredentialsTest() throws Exception {

    CleartextCredentials cleartextCredentials = OpaqueUtils.createCleartextCredentials(
      Hex.decode("01"),
      Hex.decode("02"),
      Hex.decode("03"),
      Hex.decode("04")
    );
    assertArrayEquals(Hex.decode("01"), cleartextCredentials.serverPublicKey());
    assertArrayEquals(Hex.decode("03"), cleartextCredentials.serverIdentity());
    assertArrayEquals(Hex.decode("04"), cleartextCredentials.clientIdentity());

    CleartextCredentials ctc2 = OpaqueUtils.createCleartextCredentials(
      Hex.decode("01"),
      Hex.decode("02"),
      null, null
    );
    assertArrayEquals(Hex.decode("01"), ctc2.serverPublicKey());
    assertArrayEquals(Hex.decode("01"), ctc2.serverIdentity());
    assertArrayEquals(Hex.decode("02"), ctc2.clientIdentity());

  }

  private void checkRandomness(byte[] random, int deviation) throws IOException {

    int[] distribution = new int[256];

    for (int i = 0; i < random.length; i++) {
      int intValue = new BigInteger(new byte[] { 0x00, random[i] }).intValue();
      distribution[intValue]++;
    }
    log.info("Random distribution: {}", distribution);

    //int expected = random.length / 256;
    int lowest = distribution[0];
    int highest = distribution[0];
    for (int i = 0; i < 256; i++) {
      lowest = Math.min(lowest, distribution[i]);
      highest = Math.max(highest, distribution[i]);
    }
    log.info("Lowest char count: {}, highest: {} - Difference: {}", lowest, highest, highest - lowest);
    if ((highest - lowest) > deviation) {
      throw new IOException("Random max deviation exceeded");
    }

    log.info("Randomness test passed");
  }

}
