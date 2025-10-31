// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Invalid input exception.
 */

public class InvalidInputException extends Exception {
  @Serial
  private static final long serialVersionUID = -1577241287239620312L;

  /**
   * Constructs a new invalid input exception with the specified detail message.
   *
   * @param message the detail message
   */
  public InvalidInputException(String message) {
    super(message);
  }

  /**
   * Constructs a new invalid input exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause
   */
  public InvalidInputException(String message, Throwable cause) {
    super(message, cause);
  }
}
