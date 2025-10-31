// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server.keys;

/**
 * Derived Keys Record
 */
public record DerivedKeys(
    /* A MAC authentication key */
    byte[] km2,
    /* A MAC authentication key */
    byte[] km3,
    /* The shared session key */
    byte[] sessionKey) {
}
