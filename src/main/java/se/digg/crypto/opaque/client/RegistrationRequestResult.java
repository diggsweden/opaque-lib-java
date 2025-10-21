// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.RegistrationRequest;

/**
 * Registration request data record
 */
public record RegistrationRequestResult(
  RegistrationRequest registrationRequest,
  byte[] blind) {
}
