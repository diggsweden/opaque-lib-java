package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Invalid input exception
 */
public class InvalidInputException extends Exception{
  @Serial private static final long serialVersionUID = -1577241287239620312L;

  /** {@inheritDoc} */
  public InvalidInputException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public InvalidInputException(String message, Throwable cause) {
    super(message, cause);
  }
}
