package se.digg.crypto.opaque.dto;

import java.util.List;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Key Exchange message 2 record
 */
public record KE2(
  CredentialResponse credentialResponse,
  AuthResponse authResponse
) {

  public static KE2 fromBytes(byte[] ke2Bytes, int nonceLen, int macLen, int elementSerializationSize) throws InvalidInputException {
    int authResponseLen = elementSerializationSize + nonceLen + macLen;
    int credentialResponseLen = ke2Bytes.length - authResponseLen;
    List<byte[]> split = OpaqueUtils.split(ke2Bytes, credentialResponseLen);
    return new KE2(
      CredentialResponse.fromBytes(split.get(0), elementSerializationSize, nonceLen),
      AuthResponse.fromBytes(split.get(1), nonceLen, macLen)
    );
  }

  public byte[] getEncoded() {
    return Arrays.concatenate(credentialResponse.getEncoded(), authResponse.getEncoded());
  }

}
