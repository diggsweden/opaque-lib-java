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

/**
 * The Envelope record encapsulates a cryptographic envelope containing a nonce and an authentication tag.
 * This data type is defined in OPAQUE.
 *
 * @param nonce   The nonce value in the OPAQUE envelope.
 * @param authTag The authentication tag in the OPAQUE envelope.
 */
public record Envelope(
  byte[] nonce,
  byte[] authTag
) {

  /**
   * Constructs an {@code Envelope} object from its byte-encoded representation.
   * <p>
   * This method parses the provided byte array to extract the nonce and the remaining data,
   * which typically represents the authentication tag.
   *
   * @param envelopeBytes the byte array containing the encoded {@code Envelope}.
   * @param nonceLength the fixed length of the nonce in bytes.
   * @return an instance of {@code Envelope} with the extracted nonce and authentication tag.
   * @throws InvalidInputException if the provided byte array is invalid or has insufficient length
   *                               to extract the nonce and authentication tag as expected.
   */
  public static Envelope fromBytes(byte[] envelopeBytes, int nonceLength) throws InvalidInputException {

    TLSSyntaxParser parser = new TLSSyntaxParser(envelopeBytes);
    return new Envelope(
      parser.extractFixedLength(nonceLength),
      parser.getData()
    );
  }

  /**
   * Returns the encoded representation of this {@code Envelope}. This representation
   * is formed by concatenating the {@code nonce} and the {@code authTag} fields.
   *
   * @return a byte array containing the concatenated nonce and authentication tag.
   */
  public byte[] getEncoded(){
    return Arrays.concatenate(nonce, authTag);
  }

}
