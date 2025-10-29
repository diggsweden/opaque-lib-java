// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxEncoder;

/**
 * Cleartext credentials record
 */
public record CleartextCredentials(
  byte[] serverPublicKey,
  byte[] serverIdentity,
  byte[] clientIdentity
) {
  public byte[] serialize() throws InvalidInputException {
    return TLSSyntaxEncoder.getInstance()
      .addFixedLengthData(serverPublicKey)
      .addVariableLengthData(serverIdentity, 2)
      .addVariableLengthData(clientIdentity, 2)
      .toBytes();
  }
}
