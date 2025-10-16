package se.digg.crypto.opaque.error;

import java.io.Serial;

/**
 * Exception when deserializing data
 */
public class DeserializationException extends Exception {
  @Serial private static final long serialVersionUID = 8398814732127715345L;

  /** {@inheritDoc} */
  public DeserializationException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public DeserializationException(String message, Throwable cause) {
    super(message, cause);
  }
}
