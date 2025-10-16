package se.digg.crypto.opaque.crypto;

/**
 * Data class for a server private key
 */
public record ServerPrivateKey<T extends Object>(T privateKey) {
}
