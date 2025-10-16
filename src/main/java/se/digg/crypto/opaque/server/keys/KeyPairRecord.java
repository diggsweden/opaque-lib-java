package se.digg.crypto.opaque.server.keys;

/**
 * Key pair data records
 */
public record KeyPairRecord(
  byte[] publicKey,
  byte[] privateKey
) {
}
