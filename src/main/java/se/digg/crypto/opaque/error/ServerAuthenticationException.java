// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * ServerAuthentication exception
 */
public class ServerAuthenticationException extends Exception {
  @Serial private static final long serialVersionUID = 6275036828809751883L;

  /** {@inheritDoc} */
  public ServerAuthenticationException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public ServerAuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }
}
