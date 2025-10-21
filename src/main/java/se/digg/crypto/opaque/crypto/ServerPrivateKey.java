// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

/**
 * Data class for a server private key
 */
public record ServerPrivateKey<T extends Object>(T privateKey) {
}
