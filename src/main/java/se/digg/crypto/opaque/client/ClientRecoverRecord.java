// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Client credential recovery record
 */
public record ClientRecoverRecord(
    KeyPairRecord clientKeyPair,
    CleartextCredentials cleartextCredentials,
    byte[] exportKey) {
}
