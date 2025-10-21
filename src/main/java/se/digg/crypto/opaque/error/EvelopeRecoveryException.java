// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Envelope recovery errors
 */
public class EvelopeRecoveryException extends Exception{
  @Serial private static final long serialVersionUID = -235428289520652761L;

  public EvelopeRecoveryException(String message) {
    super(message);
  }

  public EvelopeRecoveryException(String message, Throwable cause) {
    super(message, cause);
  }
}
