package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Derive key pair error exception
 */
public class DeriveKeyPairErrorException extends Exception{
  @Serial private static final long serialVersionUID = -3914184956788230653L;

  /** {@inheritDoc} */
  public DeriveKeyPairErrorException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public DeriveKeyPairErrorException(String message, Throwable cause) {
    super(message, cause);
  }
}
