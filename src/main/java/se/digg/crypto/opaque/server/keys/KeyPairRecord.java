// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server.keys;

/**
 * Key pair data records
 */
public record KeyPairRecord(
  byte[] publicKey,
  byte[] privateKey
) {
}
