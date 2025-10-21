// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import java.security.KeyPair;

import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Client credential recovery record
 */
public record ClientRecoverRecord(
  KeyPairRecord clientKeyPair,
  CleartextCredentials cleartextCredentials,
  byte[] exportKey
) {
}
