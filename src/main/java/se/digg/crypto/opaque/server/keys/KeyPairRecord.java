// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server.keys;

/**
 * Key pair data records
 */
public record KeyPairRecord(
    byte[] publicKey,
    byte[] privateKey) {
}
