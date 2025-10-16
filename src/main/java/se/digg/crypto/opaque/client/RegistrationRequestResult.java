package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.RegistrationRequest;

/**
 * Registration request data record
 */
public record RegistrationRequestResult(
  RegistrationRequest registrationRequest,
  byte[] blind) {
}
