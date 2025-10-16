package se.digg.crypto.opaque.dto;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * AuthRequestRecord
 */
public record AuthRequest(
  byte[] clientNonce,
  byte[] clientPublicKey
) {

  public static AuthRequest fromBytes(byte[] authRequestBytes, int nonceLength) throws InvalidInputException {

    TLSSyntaxParser parser = new TLSSyntaxParser(authRequestBytes);
    return new AuthRequest(
      parser.extractFixedLength(nonceLength),
      parser.getData()
    );
  }

  public byte[] getEncoded(){
    return Arrays.concatenate(clientNonce, clientPublicKey);
  }

}
