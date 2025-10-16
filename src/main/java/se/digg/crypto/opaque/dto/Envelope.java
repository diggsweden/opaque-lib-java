package se.digg.crypto.opaque.dto;

import java.util.List;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxEncoder;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * Envelope data structure
 */
public record Envelope(
  byte[] nonce,
  byte[] authTag
) {

  public static Envelope fromBytes(byte[] envelopeBytes, int nonceLength) throws InvalidInputException {

    TLSSyntaxParser parser = new TLSSyntaxParser(envelopeBytes);
    return new Envelope(
      parser.extractFixedLength(nonceLength),
      parser.getData()
    );
  }

  public byte[] getEncoded(){
    return Arrays.concatenate(nonce, authTag);
  }

}
