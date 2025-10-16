package se.digg.crypto.opaque.dto;

/**
 * Registration request record
 */
public record RegistrationRequest(
  /* A serialized OPRF group element */
  byte[] blindedMessage
) {

  public static RegistrationRequest fromBytes(byte[] registrationRequestBytes) {
    return new RegistrationRequest(registrationRequestBytes);
  }

  public byte[] getEncoded() {
    return blindedMessage;
  }

}
