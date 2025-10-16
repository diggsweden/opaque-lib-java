package se.digg.crypto.opaque.dto;

/**
 * CredentialRequestRecord
 */
public record CredentialRequest(
  byte[] blindedMessage
) {

  public static CredentialRequest fromBytes(byte[] blindedMessage){
    return new CredentialRequest(blindedMessage);
  }

  public byte[] getEncoded() {
    return blindedMessage;
  }

}
