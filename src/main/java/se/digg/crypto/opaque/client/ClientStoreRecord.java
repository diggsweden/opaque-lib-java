package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.Envelope;

/**
 * Client OPAQUE store function output result
 */
public record ClientStoreRecord(
  Envelope envelope,
  byte[] clientPublicKey,
  byte[] maskingKey,
  byte[] exportKey

) {
}
