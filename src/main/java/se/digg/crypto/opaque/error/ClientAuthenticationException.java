// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Client authentication exception
 */
public class ClientAuthenticationException extends Exception {

  @Serial private static final long serialVersionUID = 8080070838494889334L;

  /** {@inheritDoc} */
  public ClientAuthenticationException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public ClientAuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }
}
