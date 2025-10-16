package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.CredentialRequest;

/**
 * Create credential request result
 */
public record CredentialRequestData(
  CredentialRequest credentialRequest,
  byte[] blind
) {
}
