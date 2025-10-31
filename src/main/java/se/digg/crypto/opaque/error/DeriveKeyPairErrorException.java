// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Derive key pair error exception.
 */

public class DeriveKeyPairErrorException extends Exception {
  @Serial
  private static final long serialVersionUID = -3914184956788230653L;

  /**
   * Constructs a new derive key pair error exception with the specified detail message.
   *
   * @param message the detail message
   */
  public DeriveKeyPairErrorException(String message) {
    super(message);
  }

  /**
   * Constructs a new derive key pair error exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause
   */
  public DeriveKeyPairErrorException(String message, Throwable cause) {
    super(message, cause);
  }
}
