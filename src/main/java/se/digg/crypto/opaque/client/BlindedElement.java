// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Blinded Element.
 */

public record BlindedElement(

    /* Blind data (scalar) used to revert blinding of the blinded element */
    byte[] blind,
    /* Blinded element (EC point) */
    ECPoint blindElement) {
}
