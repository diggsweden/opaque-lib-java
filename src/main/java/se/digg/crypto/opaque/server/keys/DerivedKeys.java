package se.digg.crypto.opaque.server.keys;

/**
 * Derived Keys Record
 */
public record DerivedKeys(
  /* A MAC authentication key */
  byte[] km2,
  /* A MAC authentication key */
  byte[] km3,
  /* The shared session key */
  byte[] sessionKey
) {
}
