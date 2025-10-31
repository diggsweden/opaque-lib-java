// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

import org.bouncycastle.util.Arrays;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * CredentialResponse record.
 */

public record CredentialResponse(
    byte[] evaluatedMessage,
    byte[] maskingNonce,
    byte[] maskedResponse) {

  public static CredentialResponse fromBytes(byte[] credentialResponseBytes,
      int elementSerializationSize, int nonceLen) throws InvalidInputException {
    TLSSyntaxParser parser = new TLSSyntaxParser(credentialResponseBytes);
    return new CredentialResponse(
        parser.extractFixedLength(elementSerializationSize),
        parser.extractFixedLength(nonceLen),
        parser.getData());
  }

  public byte[] getEncoded() {
    return Arrays.concatenate(evaluatedMessage, maskingNonce, maskedResponse);
  }

}
