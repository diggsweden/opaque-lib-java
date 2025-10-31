// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

import org.bouncycastle.util.Arrays;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * Registration record.
 */

public record RegistrationRecord(
    /* The client's encoded public key, corresponding to the private key client_private_key. */
    byte[] clientPublicKey,
    /*
     * An encryption key used by the server with the sole purpose of defending against client
     * enumeration attacks.
     */
    byte[] maskingKey,
    /* The client's Envelope structure */
    Envelope envelope) {

  public static RegistrationRecord fromBytes(byte[] registrationRecordBytes, int clientPkLen,
      int hashLen, int nonceLen) throws InvalidInputException {
    // int envelopeLen = registrationRecordBytes.length - (clientPkLen + hashLen);
    TLSSyntaxParser parser = new TLSSyntaxParser(registrationRecordBytes);
    return new RegistrationRecord(
        parser.extractFixedLength(clientPkLen),
        parser.extractFixedLength(hashLen),
        Envelope.fromBytes(parser.getData(), nonceLen));
  }

  public byte[] getEncoded() {
    return Arrays.concatenate(clientPublicKey, maskingKey, envelope.getEncoded());
  }

}
