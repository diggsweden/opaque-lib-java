// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.dto;

import org.bouncycastle.util.Arrays;

import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.protocol.TLSSyntaxParser;

/**
 * Registration response record
 */
public record RegistrationResponse(
  /* A serialized OPRF group element */
  byte[] evaluatedMessage,
  /* The server's encoded public key that will be used for the online AKE stage. */
  byte[] serverPublicKey
) {

  public static RegistrationResponse fromBytes(byte[] registrationResponseBytes, int elementSerializationSize)
    throws InvalidInputException {
    TLSSyntaxParser parser = new TLSSyntaxParser(registrationResponseBytes);
    return new RegistrationResponse(
      parser.extractFixedLength(elementSerializationSize),
      parser.getData()
    );
  }

  public byte[] getEncoded() {
    return Arrays.concatenate(evaluatedMessage, serverPublicKey);
  }

}
