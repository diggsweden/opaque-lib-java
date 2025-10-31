// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * ServerAuthentication exception.
 */

public class ServerAuthenticationException extends Exception {
  @Serial
  private static final long serialVersionUID = 6275036828809751883L;

  /**
   * Constructs a new server authentication exception with the specified detail message.
   *
   * @param message the detail message
   */
  public ServerAuthenticationException(String message) {
    super(message);
  }

  /**
   * Constructs a new server authentication exception with the specified detail message and cause.
   *
   * @param message the detail message
   * @param cause the cause
   */
  public ServerAuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }
}
