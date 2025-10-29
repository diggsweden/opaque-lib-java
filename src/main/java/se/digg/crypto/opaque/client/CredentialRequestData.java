// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.CredentialRequest;

/**
 * Create credential request result
 */
public record CredentialRequestData(
  CredentialRequest credentialRequest,
  byte[] blind
) {
}
