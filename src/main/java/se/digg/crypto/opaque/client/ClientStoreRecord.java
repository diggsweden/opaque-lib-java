// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.Envelope;

/**
 * Client OPAQUE store function output result
 */
public record ClientStoreRecord(
  Envelope envelope,
  byte[] clientPublicKey,
  byte[] maskingKey,
  byte[] exportKey

) {
}
