// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server;

import java.security.KeyPair;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.ClientAuthenticationException;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Interface for the Opaque server implementation.
 */

public interface OpaqueServer {

  /**
   * Create registration response data to the client.
   *
   * @param registrationRequest registration request received from the client.
   * @param serverPublicKey the server public key.
   * @param credentialIdentifier credential identifier.
   * @param oprfSeed oprf seed used to derive the OPRF key pair.
   * @return registration response to be returned to the client.
   * @throws DeserializationException error parsing EC point element data.
   * @throws DeriveKeyPairErrorException error deriving key pairs
   */
  RegistrationResponse createRegistrationResponse(byte[] registrationRequest,
      byte[] serverPublicKey, byte[] credentialIdentifier, byte[] oprfSeed)
      throws DeserializationException,
      DeriveKeyPairErrorException;

  /**
   * Generate KE2 data for the authentication flow.
   *
   * @param serverIdentity server identity.
   * @param serverPrivateKey server private key.
   * @param serverPublicKey server public key.
   * @param registrationRecord saved registration record for this client.
   * @param credentialIdentifier credential identifier.
   * @param oprfSeed oprf seed used to derive the OPRF key pair.
   * @param ke1 KE1 received from the client.
   * @param clientIdentity client identity.
   * @param state empty server state to be used to store state information.
   * @return KE2 data object to be returned to the client.
   * @throws DeserializationException error parsing EC point element data.
   * @throws DeriveKeyPairErrorException error deriving key pairs.
   * @throws InvalidInputException invalid input
   */
  KE2 generateKe2(byte[] serverIdentity, OprfPrivateKey serverPrivateKey, byte[] serverPublicKey,
      byte[] registrationRecord, byte[] credentialIdentifier, byte[] oprfSeed, byte[] ke1,
      byte[] clientIdentity, ServerState state)
      throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException;

  /**
   * Perform server finished operation.
   *
   * @param ke3 the KE3 object received from the client.
   * @param state state information.
   * @return the client Mac as verification that login succeeded.
   * @throws ClientAuthenticationException error authenticating the client
   */
  byte[] serverFinish(byte[] ke3, ServerState state) throws ClientAuthenticationException;

  void setStaticOprfKeyPair(KeyPair keyPair);

}
