// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.EvelopeRecoveryException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.error.ServerAuthenticationException;

/**
 * Interface for the OPAQUE client.
 */

public interface OpaqueClient {

  /**
   * Creates a password registration request to the Opaque server.
   *
   * @param password password.
   * @return registration result.
   * @throws DeriveKeyPairErrorException error deriving key pair
   */
  RegistrationRequestResult createRegistrationRequest(byte[] password)
      throws DeriveKeyPairErrorException;

  /**
   * Client finalize registration request.
   *
   * @param password the user password.
   * @param blind the blind used to blind the OPRF request.
   * @param registrationRespons registration response received from the server.
   * @param serverIdentity server identity.
   * @param clientIdentity client identity.
   * @return Registration finalization result containing data to store and data to return to the
   *         server.
   * @throws DeserializationException error deserializing data.
   * @throws DeriveKeyPairErrorException error deriving key paris.
   * @throws InvalidInputException invalid inputs
   */
  RegistrationFinalizationResult finalizeRegistrationRequest(byte[] password, byte[] blind,
      byte[] registrationRespons,
      byte[] serverIdentity, byte[] clientIdentity)
      throws DeserializationException, DeriveKeyPairErrorException, InvalidInputException;

  /**
   * Create the KE1 authentication exchange data.
   *
   * @param password the user password.
   * @param clientState a new client state object that will be used to store client state
   *        information.
   * @return KE1 data to send to the server.
   * @throws DeriveKeyPairErrorException error deriving key paris
   */
  KE1 generateKe1(byte[] password, ClientState clientState) throws DeriveKeyPairErrorException;

  /**
   * Generate the KE3 authentication exchange data.
   *
   * @param clientIdentity client identity.
   * @param serverIdentity server identity.
   * @param ke2 KE2 data received from the server.
   * @param clientState client state data passed from the ongoing authentication session.
   * @return KE3 data object to be forwarded to the server.
   * @throws EvelopeRecoveryException Error recovering envelope data.
   * @throws DeriveKeyPairErrorException error deriving key paris.
   * @throws DeserializationException error parsing element data.
   * @throws ServerAuthenticationException error authenticating the server.
   * @throws InvalidInputException invalid input
   */
  ClientKeyExchangeResult generateKe3(byte[] clientIdentity, byte[] serverIdentity, byte[] ke2,
      ClientState clientState)
      throws EvelopeRecoveryException, DeriveKeyPairErrorException, DeserializationException,
      ServerAuthenticationException, InvalidInputException;

}
