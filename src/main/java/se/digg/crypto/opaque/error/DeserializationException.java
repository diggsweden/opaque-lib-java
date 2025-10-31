// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Exception when deserializing data.
 */

public class DeserializationException extends Exception {
  @Serial
  private static final long serialVersionUID = 8398814732127715345L;

  /**
   * Constructs a new deserialization exception with the specified detail message.
   *
   * @param message the detail message
   */
  public DeserializationException(String message) {
    super(message);
  }

  /**
   * Constructs a new deserialization exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause
   */
  public DeserializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
