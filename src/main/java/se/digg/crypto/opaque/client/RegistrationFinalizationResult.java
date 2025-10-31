// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.RegistrationRecord;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public record RegistrationFinalizationResult(
    RegistrationRecord registrationRecord,
    byte[] exportKey) {
}
