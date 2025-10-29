// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

import java.util.List;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Key Exchange message 2 record
 */
public record KE1(
  CredentialRequest credentialRequest,
  AuthRequest authRequest
) {

  public static KE1 fromBytes(byte[] ke1Bytes, int blindedMessageLen, int nonceLength) throws InvalidInputException {
    List<byte[]> split = OpaqueUtils.split(ke1Bytes, blindedMessageLen);
    return new KE1(
      CredentialRequest.fromBytes(split.get(0)),
      AuthRequest.fromBytes(split.get(1), nonceLength)
    );
  }

  public byte[] getEncoded(){
    return Arrays.concatenate(credentialRequest.getEncoded(), authRequest.getEncoded());
  }
}
