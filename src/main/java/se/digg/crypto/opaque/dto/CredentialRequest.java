// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

/**
 * CredentialRequestRecord
 */
public record CredentialRequest(
  byte[] blindedMessage
) {

  public static CredentialRequest fromBytes(byte[] blindedMessage){
    return new CredentialRequest(blindedMessage);
  }

  public byte[] getEncoded() {
    return blindedMessage;
  }

}
