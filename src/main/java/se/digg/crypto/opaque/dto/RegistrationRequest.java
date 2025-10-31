// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

/**
 * Registration request record.
 */

public record RegistrationRequest(
    /* A serialized OPRF group element */
    byte[] blindedMessage) {

  public static RegistrationRequest fromBytes(byte[] registrationRequestBytes) {
    return new RegistrationRequest(registrationRequestBytes);
  }

  public byte[] getEncoded() {
    return blindedMessage;
  }

}
