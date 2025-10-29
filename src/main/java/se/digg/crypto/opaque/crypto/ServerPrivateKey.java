// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

/**
 * Data class for a server private key
 */
public record ServerPrivateKey<T extends Object>(T privateKey) {
}
