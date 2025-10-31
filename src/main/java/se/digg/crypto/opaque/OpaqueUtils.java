// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.client.CleartextCredentials;
import se.digg.crypto.opaque.dto.CredentialResponse;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxEncoder;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Opaque Utility functions
 */
public class OpaqueUtils {

  private static final Random RNG = new SecureRandom();

  /**
   * Concatenate parts to a byte array
   *
   * @param parts each part must be a byte array or a UTF-8 encoded string
   * @return concatenated byte array
   */
  public static byte[] concat(Object... parts) {

    if (parts == null) {
      return new byte[] {};
    }
    byte[] concatenatedData = new byte[] {};
    for (Object o : parts) {
      if (o instanceof byte[]) {
        concatenatedData = Arrays.concatenate(concatenatedData, (byte[]) o);
        continue;
      }
      if (o instanceof String) {
        concatenatedData =
            Arrays.concatenate(concatenatedData, ((String) o).getBytes(StandardCharsets.UTF_8));
        continue;
      }
      throw new IllegalArgumentException("Illegal data to concatenate: " + o);
    }
    return concatenatedData;
  }

  public static byte[] random(int byteLen) {
    byte[] newRandomParam = new byte[byteLen];
    RNG.nextBytes(newRandomParam);
    return newRandomParam;
  }

  public static byte[] zeroes(int byteLen) {
    byte[] zeroBytes = new byte[byteLen];
    Arrays.fill(zeroBytes, (byte) 0x00);
    return zeroBytes;
  }

  public static byte[] xor(byte[] arg1, byte[] arg2) throws InvalidInputException {
    Objects.requireNonNull(arg1, "XOR argument must not be null");
    Objects.requireNonNull(arg2, "XOR argument must not be null");

    if (arg1.length != arg2.length) {
      throw new InvalidInputException("XOR operation on parameters of different lengths");
    }
    byte[] xorArray = new byte[arg1.length];
    for (int i = 0; i < arg1.length; i++) {
      xorArray[i] = (byte) (arg1[i] ^ arg2[i]);
    }
    return xorArray;
  }

  public static List<byte[]> split(byte[] concatenatedData, int index)
      throws InvalidInputException {
    TLSSyntaxParser parser = new TLSSyntaxParser(concatenatedData);
    List<byte[]> byteArrayList = new ArrayList<>();
    byteArrayList.add(parser.extractFixedLength(index));
    byteArrayList.add(parser.getData());
    return byteArrayList;
  }

  public static byte[] i2osp(int val, int len) throws InvalidInputException {
    byte[] lengthVal = new BigInteger(String.valueOf(val)).toByteArray();
    byte[] paddedLengthVal = lengthVal.clone();
    if (paddedLengthVal.length > 1 && paddedLengthVal[0] == 0x00) {
      // Remove leading 00
      paddedLengthVal = Arrays.copyOfRange(paddedLengthVal, 1, paddedLengthVal.length);
    }
    if (paddedLengthVal.length > len) {
      throw new InvalidInputException("Value require more bytes than the assigned length size");
    }

    if (paddedLengthVal.length < len) {
      // Pad up to expected size
      for (int i = paddedLengthVal.length; i < len; i++) {
        paddedLengthVal = Arrays.concatenate(new byte[] {0x00}, paddedLengthVal);
      }
    }
    return paddedLengthVal;
  }

  public static BigInteger os2ip(byte[] val) {
    // Make sure we get a positive value by adding 0x00 as leading byte in the value byte array
    return new BigInteger(Arrays.concatenate(new byte[] {0x00}, val));
  }

  public static byte[] preamble(
      byte[] clientIdentity, KE1 ke1, byte[] serverIdentity, CredentialResponse credentialResponse,
      byte[] serverNonce,
      byte[] serverPublicKeyshare, byte[] context) throws InvalidInputException {
    return concat(
        "OPAQUEv1-",
        new TLSSyntaxEncoder()
            .addVariableLengthData(context, 2)
            .addVariableLengthData(clientIdentity, 2)
            .addFixedLengthData(ke1.getEncoded())
            .addVariableLengthData(serverIdentity, 2)
            .addFixedLengthData(credentialResponse.getEncoded())
            .addFixedLengthData(serverNonce)
            .addFixedLengthData(serverPublicKeyshare)
            .toBytes());
  }

  public static CleartextCredentials createCleartextCredentials(
      byte[] serverPublicKey, byte[] clientPublicKey,
      byte[] serverIdentity, byte[] clientIdentity) {
    return new CleartextCredentials(
        serverPublicKey,
        serverIdentity != null ? serverIdentity : serverPublicKey,
        clientIdentity != null ? clientIdentity : clientPublicKey);
  }

  public static KeyPair getKeyPair(KeyPairRecord keyPairRecord, ECParameterSpec parameterSpec)
      throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
      DeserializationException {
    return new KeyPair(getPublicECKey(keyPairRecord.publicKey(), parameterSpec),
        getPrivateECKey(keyPairRecord.privateKey(), parameterSpec));
  }

  public static PrivateKey getPrivateECKey(byte[] privateKeyBytes, ECParameterSpec parameterSpec)
      throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
    ECPrivateKeySpec privateKeySpec =
        new ECPrivateKeySpec(new BigInteger(1, privateKeyBytes), parameterSpec);
    KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
    return keyFactory.generatePrivate(privateKeySpec);
  }

  public static PublicKey getPublicECKey(byte[] publicKeyBytes, ECParameterSpec parameterSpec)
      throws DeserializationException, NoSuchAlgorithmException, NoSuchProviderException,
      InvalidKeySpecException {
    ECPoint ecPointElement = parameterSpec.getCurve().decodePoint(publicKeyBytes);
    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPointElement, parameterSpec);
    KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
    return keyFactory.generatePublic(publicKeySpec);
  }


}
