// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.KE3;

/**
 * Client key exchange result
 */
public record ClientKeyExchangeResult(
  KE3 ke3,
  byte[] sessionKey,
  byte[] exportKey
) {
}
