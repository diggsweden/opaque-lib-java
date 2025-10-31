// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client.impl;

import java.util.Arrays;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;

import lombok.RequiredArgsConstructor;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.AuthClientFinalizeResult;
import se.digg.crypto.opaque.client.BlindedElement;
import se.digg.crypto.opaque.client.CleartextCredentials;
import se.digg.crypto.opaque.client.ClientAkeState;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientRecoverRecord;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.ClientStoreRecord;
import se.digg.crypto.opaque.client.CredentialRequestData;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.dto.AuthRequest;
import se.digg.crypto.opaque.dto.CredentialRequest;
import se.digg.crypto.opaque.dto.CredentialResponse;
import se.digg.crypto.opaque.dto.Envelope;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.dto.RegistrationRequest;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.EvelopeRecoveryException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.error.ServerAuthenticationException;
import se.digg.crypto.opaque.server.keys.DerivedKeys;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Default implementation of the Opaque client
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultOpaqueClient implements OpaqueClient {

  /** OPRF functions */
  protected final OprfFunctions oprf;
  /** Key derivation functions */
  protected final KeyDerivationFunctions keyDerivation;
  /** Hash, hmac and stretch functions */
  protected final HashFunctions hashFunctions;


  /** {@inheritDoc} */
  @Override
  public RegistrationRequestResult createRegistrationRequest(byte[] password)
      throws DeriveKeyPairErrorException {
    log.debug("Creating OPAQUE registration request");
    BlindedElement blindData = oprf.blind(password);
    byte[] blindedMessage = oprf.serializeElement(blindData.blindElement());
    RegistrationRequest request = new RegistrationRequest(blindedMessage);
    return new RegistrationRequestResult(request, blindData.blind());
  }

  /** {@inheritDoc} */
  @Override
  public RegistrationFinalizationResult finalizeRegistrationRequest(byte[] password, byte[] blind,
      byte[] registrationResponseBytes,
      byte[] serverIdentity, byte[] clientIdentity)
      throws DeserializationException, DeriveKeyPairErrorException, InvalidInputException {
    log.debug("Finalizing OPAQUE registration");

    RegistrationResponse registrationRespons =
        RegistrationResponse.fromBytes(registrationResponseBytes,
            oprf.getOPRFSerializationSize());

    ECPoint evalueatedElement = oprf.deserializeElement(registrationRespons.evaluatedMessage());
    byte[] oprfOutput = oprf.finalize(password, blind, evalueatedElement);
    byte[] stretchedOprfOutput = hashFunctions.stretch(oprfOutput);
    byte[] randomizedPassword =
        keyDerivation.extract(new byte[] {}, OpaqueUtils.concat(oprfOutput, stretchedOprfOutput));
    ClientStoreRecord clientStoreRecord =
        store(randomizedPassword, registrationRespons.serverPublicKey(), serverIdentity,
            clientIdentity);
    RegistrationRecord registrationRecord =
        new RegistrationRecord(clientStoreRecord.clientPublicKey(),
            clientStoreRecord.maskingKey(), clientStoreRecord.envelope());

    return new RegistrationFinalizationResult(registrationRecord, clientStoreRecord.exportKey());
  }

  /** {@inheritDoc} */
  @Override
  public KE1 generateKe1(byte[] password, ClientState state) throws DeriveKeyPairErrorException {
    log.debug("Generating OPAQUE KE1");
    CredentialRequestData credentialRequestData = createCredentialRequest(password);
    state.setPassword(password);
    state.setBlind(credentialRequestData.blind());
    return authClientStart(credentialRequestData.credentialRequest(), state.getClientAkeState());
  }

  /** {@inheritDoc} */
  @Override
  public ClientKeyExchangeResult generateKe3(byte[] clientIdentity, byte[] serverIdentity,
      byte[] ke2Bytes, ClientState clientState)
      throws EvelopeRecoveryException, DeriveKeyPairErrorException, DeserializationException,
      ServerAuthenticationException, InvalidInputException {
    log.debug("Generating OPAQUE KE3");
    KE2 ke2 = KE2.fromBytes(ke2Bytes, keyDerivation.getNonceSize(), hashFunctions.getMacSize(),
        oprf.getOPRFSerializationSize());
    ClientRecoverRecord clientRecoverRecord =
        recoverCredentials(clientState.getPassword(), clientState.getBlind(),
            ke2.credentialResponse(), serverIdentity, clientIdentity);
    AuthClientFinalizeResult authClientFinalizeResult =
        authClientFinalize(clientRecoverRecord.cleartextCredentials(),
            clientRecoverRecord.clientKeyPair().privateKey(), ke2, clientState);
    return new ClientKeyExchangeResult(authClientFinalizeResult.ke3(),
        authClientFinalizeResult.sessionKey(), clientRecoverRecord.exportKey());
  }

  /**
   * Creates client store record by deriving various cryptographic keys and creating an encrypted
   * envelope. This record is used for interim storage of client key derivation data in OPAQUE
   * client operations. This is the output of the store function defined in OPAQUE.
   *
   * @param randomizedPassword The processed password used for secure key derivation.
   * @param serverPublicKey The public key of the server used in key agreement operations.
   * @param serverIdentity The identity of the server as a byte array.
   * @param clientIdentity The identity of the client as a byte array.
   * @return A {@code ClientStoreRecord} The record.
   * @throws DeriveKeyPairErrorException If an error occurs during the derivation of the key pair.
   * @throws InvalidInputException If the input values are invalid or improperly formatted.
   */
  protected ClientStoreRecord store(byte[] randomizedPassword, byte[] serverPublicKey,
      byte[] serverIdentity,
      byte[] clientIdentity) throws DeriveKeyPairErrorException, InvalidInputException {
    byte[] envelopeNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] maskingKey =
        keyDerivation.expand(randomizedPassword, "MaskingKey", hashFunctions.getHashSize());
    byte[] authKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelopeNonce, "AuthKey"), hashFunctions.getHashSize());
    byte[] exportKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelopeNonce, "ExportKey"), hashFunctions.getHashSize());
    byte[] seed =
        keyDerivation.expand(randomizedPassword, OpaqueUtils.concat(envelopeNonce, "PrivateKey"),
            keyDerivation.getSeedSize());
    KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(seed);
    byte[] clientPublicKey = keyPair.publicKey();
    CleartextCredentials cleartextCredentials = OpaqueUtils.createCleartextCredentials(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] authTag = hashFunctions.mac(authKey,
        OpaqueUtils.concat(envelopeNonce, cleartextCredentials.serialize()));
    Envelope envelope = new Envelope(envelopeNonce, authTag);
    return new ClientStoreRecord(envelope, clientPublicKey, maskingKey, exportKey);
  }

  /**
   * Recovers client credentials from a secure envelope and derives cryptographic keys for further
   * operations. This is the recover function defined in OPAQUE
   *
   * @param randomizedPassword The processed password used as input to cryptographic key derivation.
   * @param serverPublicKey The public key of the server, used in the recovery process.
   * @param envelope The envelope containing nonce and authentication data for validation.
   * @param serverIdentity The identity of the server, used in cleartext credential creation.
   * @param clientIdentity The identity of the client, used in cleartext credential creation.
   * @return A {@code ClientRecoverRecord} containing the recovered cryptographic key pair,
   *         cleartext credentials, and export key.
   * @throws EvelopeRecoveryException If the envelope's authentication tag does not match the
   *         expected value.
   * @throws DeriveKeyPairErrorException If an error occurs during the derivation of the
   *         Diffie-Hellman key pair.
   * @throws InvalidInputException If the input parameters have invalid or incorrect formats.
   */
  protected ClientRecoverRecord recover(byte[] randomizedPassword, byte[] serverPublicKey,
      Envelope envelope,
      byte[] serverIdentity, byte[] clientIdentity)
      throws EvelopeRecoveryException, DeriveKeyPairErrorException, InvalidInputException {
    byte[] authKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelope.nonce(), "AuthKey"), hashFunctions.getHashSize());
    byte[] exportKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelope.nonce(), "ExportKey"), hashFunctions.getHashSize());
    byte[] seed =
        keyDerivation.expand(randomizedPassword, OpaqueUtils.concat(envelope.nonce(), "PrivateKey"),
            keyDerivation.getSeedSize());
    KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(seed);
    byte[] clientPublicKey = keyPair.publicKey();
    CleartextCredentials cleartextCredentials = OpaqueUtils.createCleartextCredentials(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

    byte[] expectedTag = hashFunctions.mac(authKey,
        OpaqueUtils.concat(envelope.nonce(), cleartextCredentials.serialize()));
    if (!Arrays.equals(envelope.authTag(), expectedTag)) {
      throw new EvelopeRecoveryException("Envelope auth tag mismatch");
    }
    return new ClientRecoverRecord(keyPair, cleartextCredentials, exportKey);
  }

  /**
   * Creates a credential request using the given password. This involves blinding the password to
   * generate a blinded message and its corresponding blind data. The method returns a
   * {@code CredentialRequestData} object containing the credential request and the blind used in
   * the process.
   *
   * @param password The user's password as a byte array. This is the input used for creating the
   *        blinded data and credential request.
   * @return An instance of {@code CredentialRequestData}, encapsulating the credential request and
   *         the blind used during the process.
   * @throws DeriveKeyPairErrorException If an error occurs during the process of blinding the
   *         password or serializing the blinded element.
   */
  protected CredentialRequestData createCredentialRequest(byte[] password)
      throws DeriveKeyPairErrorException {
    BlindedElement blindData = oprf.blind(password);
    byte[] blindedMessage = oprf.serializeElement(blindData.blindElement());
    CredentialRequest credentialRequest = new CredentialRequest(blindedMessage);
    return new CredentialRequestData(credentialRequest, blindData.blind());
  }

  /**
   * Recovers credentials for the client by deriving cryptographic keys and reconstructing the key
   * pair and identity information necessary for secure authentication. This method involves OPAQUE
   * protocol steps including deserialization of server data, hashing, key derivation, and envelope
   * decryption.
   *
   * @param password The user's password as a byte array.
   * @param blind The blinded password data, used as part of the OPAQUE protocol.
   * @param response The server's credential response object, containing evaluated elements and
   *        masked data.
   * @param serverIdentity The identity of the server as a byte array.
   * @param clientIdentity The identity of the client as a byte array.
   * @return A {@code ClientRecoverRecord} which contains the recovered key pair, cleartext
   *         credentials, and export key.
   * @throws DeserializationException If an error occurs while deserializing the server's evaluated
   *         element.
   * @throws EvelopeRecoveryException If an error occurs during envelope validation or recovery.
   * @throws DeriveKeyPairErrorException If an error occurs while deriving cryptographic keys.
   * @throws InvalidInputException If any of the input parameters are invalid or improperly
   *         formatted.
   */
  protected ClientRecoverRecord recoverCredentials(byte[] password, byte[] blind,
      CredentialResponse response, byte[] serverIdentity, byte[] clientIdentity)
      throws DeserializationException, EvelopeRecoveryException, DeriveKeyPairErrorException,
      InvalidInputException {

    ECPoint evaluatedElement = oprf.deserializeElement(response.evaluatedMessage());
    byte[] oprfOutput = oprf.finalize(password, blind, evaluatedElement);
    byte[] stretchedOprfOutput = hashFunctions.stretch(oprfOutput);
    byte[] randomizedPassword =
        keyDerivation.extract(new byte[] {}, OpaqueUtils.concat(oprfOutput, stretchedOprfOutput));
    byte[] maskingKey =
        keyDerivation.expand(randomizedPassword, "MaskingKey", hashFunctions.getHashSize());
    byte[] credentialResponsePad = keyDerivation.expand(maskingKey,
        OpaqueUtils.concat(response.maskingNonce(), "CredentialResponsePad"),
        keyDerivation.getNonceSize() + hashFunctions.getMacSize()
            + oprf.getOPRFSerializationSize());
    List<byte[]> concatServerPkWithEnvelope =
        OpaqueUtils.split(OpaqueUtils.xor(credentialResponsePad, response.maskedResponse()),
            oprf.getOPRFSerializationSize());
    byte[] serverPublicKey = concatServerPkWithEnvelope.get(0);
    byte[] envelope = concatServerPkWithEnvelope.get(1);
    return recover(randomizedPassword, serverPublicKey,
        Envelope.fromBytes(envelope, keyDerivation.getNonceSize()), serverIdentity, clientIdentity);
  }

  /**
   * Initiates the client-side of the authentication process by generating a key exchange message
   * (KE1) and updating the client's AKE state.
   *
   * @param credentialRequest The credential request containing the blinded password message to be
   *        sent to the server.
   * @param akeState The client's AKE state, which is updated with the client's secret key and the
   *        generated KE1 message.
   * @return The generated KE1 message which contains the credential request and authentication
   *         request to be sent to the server.
   * @throws DeriveKeyPairErrorException If an error occurs during the derivation of the
   *         Diffie-Hellman key pair.
   */
  protected KE1 authClientStart(CredentialRequest credentialRequest, ClientAkeState akeState)
      throws DeriveKeyPairErrorException {
    byte[] clientNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] clientKeyshareSeed = OpaqueUtils.random(keyDerivation.getSeedSize());
    KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(clientKeyshareSeed);
    AuthRequest authRequest = new AuthRequest(clientNonce, keyPair.publicKey());
    KE1 ke1 = new KE1(credentialRequest, authRequest);
    akeState.setClientSecret(keyPair.privateKey());
    akeState.setKe1(ke1);
    return ke1;
  }

  /**
   * Finalizes the client-side authentication process as part of the OPAQUE protocol. This involves
   * verifying server authentication, deriving shared secrets, and generating the final key exchange
   * message (KE3) to complete the mutual authentication process.
   *
   * @param cleartextCredentials The cleartext credentials containing the server's public key and
   *        identities of the client and server.
   * @param clientPrivateKey The private key of the client used to perform key agreement.
   * @param ke2 The second key exchange message from the server, containing the server's
   *        authentication response and credential response.
   * @param state The client's state object, maintaining state information necessary for the
   *        authentication process.
   * @return An {@code AuthClientFinalizeResult} containing the final key exchange message (KE3) and
   *         the derived session key for secure communication.
   * @throws ServerAuthenticationException If server authentication fails during the process due to
   *         mismatched authentication information.
   * @throws InvalidInputException If any of the input parameters are invalid or improperly
   *         formatted.
   * @throws DeserializationException If an error occurs while deserializing components of the
   *         server's response.
   */
  protected AuthClientFinalizeResult authClientFinalize(CleartextCredentials cleartextCredentials,
      byte[] clientPrivateKey, KE2 ke2, ClientState state)
      throws ServerAuthenticationException, InvalidInputException, DeserializationException {
    ClientAkeState akeState = state.getClientAkeState();

    // Derive shared secrets
    byte[] dh1 = oprf.diffieHellman(new OprfPrivateKey(akeState.getClientSecret()),
        ke2.authResponse().serverPublicKeyShare());
    byte[] dh2 = oprf.diffieHellman(new OprfPrivateKey(akeState.getClientSecret()),
        cleartextCredentials.serverPublicKey());
    byte[] dh3 = oprf.diffieHellman(new OprfPrivateKey(clientPrivateKey),
        ke2.authResponse().serverPublicKeyShare());
    byte[] ikm = OpaqueUtils.concat(dh1, dh2, dh3);

    // Derive shared key
    byte[] preamble = OpaqueUtils.preamble(cleartextCredentials.clientIdentity(), akeState.getKe1(),
        cleartextCredentials.serverIdentity(),
        ke2.credentialResponse(), ke2.authResponse().serverNonce(),
        ke2.authResponse().serverPublicKeyShare(),
        oprf.getContext());
    DerivedKeys derivedKeys = keyDerivation.deriveKeys(ikm, preamble);
    byte[] expectedServerMac = hashFunctions.mac(derivedKeys.km2(), hashFunctions.hash(preamble));

    // verify server authentication
    if (!Arrays.equals(ke2.authResponse().serverMac(), expectedServerMac)) {
      throw new ServerAuthenticationException("Server authentication failed - Server mac mismatch");
    }
    byte[] clientMac = hashFunctions.mac(derivedKeys.km3(),
        hashFunctions.hash(OpaqueUtils.concat(preamble, expectedServerMac)));
    KE3 ke3 = new KE3(clientMac);

    return new AuthClientFinalizeResult(ke3, derivedKeys.sessionKey());
  }

}
