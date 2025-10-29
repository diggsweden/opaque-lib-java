// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

/**
 * Key Exchange message 3 record
 */
public record KE3(
  byte[] clientMac
) {

  public static KE3 fromBytes(byte[] ke3Bytes) {
    return new KE3(ke3Bytes);
  }

  public byte[] getEncoded() {
    return clientMac;
  }

}
