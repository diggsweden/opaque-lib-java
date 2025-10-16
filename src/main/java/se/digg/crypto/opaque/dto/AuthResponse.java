package se.digg.crypto.opaque.dto;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * Auth response record
 */
public record AuthResponse(
  byte[] serverNonce,
  byte[] serverPublicKeyShare,
  byte[] serverMac
) {

  public static AuthResponse fromBytes(byte[] authResponseBytes, int nonceLength, int macLength) throws InvalidInputException {

    TLSSyntaxParser parser = new TLSSyntaxParser(authResponseBytes);
    return new AuthResponse(
      parser.extractFixedLength(nonceLength),
      parser.extractFixedLength(parser.getData().length - macLength),
      parser.getData()
    );
  }

  public byte[] getEncoded(){
    return Arrays.concatenate(serverNonce, serverPublicKeyShare, serverMac);
  }


}
