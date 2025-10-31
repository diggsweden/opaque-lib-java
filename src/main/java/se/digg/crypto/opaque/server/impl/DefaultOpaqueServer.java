// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server.impl;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.CleartextCredentials;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.dto.AuthResponse;
import se.digg.crypto.opaque.dto.CredentialRequest;
import se.digg.crypto.opaque.dto.CredentialResponse;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.dto.RegistrationRequest;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.ClientAuthenticationException;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.OpaqueServer;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.crypto.opaque.server.keys.DerivedKeys;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;

/**
 * Default implementation of OPAQUE server.
 */

@Slf4j
@RequiredArgsConstructor
public class DefaultOpaqueServer implements OpaqueServer {

  /** The server HSM protected private key. */
  @Setter
  protected KeyPair staticOprfKeyPair;

  /** Provider of OPRF functions. */
  protected final OprfFunctions oprf;
  /** Provider of key derivation functions. */
  protected final KeyDerivationFunctions keyDerivation;
  /** Provider of hash functions. */
  protected final HashFunctions hashFunctions;


  /** {@inheritDoc}. */
  @Override
  public RegistrationResponse createRegistrationResponse(byte[] registrationRequest,
      byte[] serverPublicKey, byte[] credentialIdentifier, byte[] oprfSeed)
      throws DeserializationException,
      DeriveKeyPairErrorException {
    log.debug("Creating OPAQUE registration response");
    RegistrationRequest request = RegistrationRequest.fromBytes(registrationRequest);
    byte[] evaluatedMessage =
        getEvaluateMessage(request.blindedMessage(), oprfSeed, credentialIdentifier);
    return new RegistrationResponse(evaluatedMessage, serverPublicKey);
  }

  /** {@inheritDoc}. */
  @Override
  public KE2 generateKe2(byte[] serverIdentity, OprfPrivateKey serverPrivateKey,
      byte[] serverPublicKey,
      byte[] registrationRecord, byte[] credentialIdentifier, byte[] oprfSeed, byte[] ke1Bytes,
      byte[] clientIdentity, ServerState state)
      throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException {
    log.debug("Generating OPAQUE KE2");
    RegistrationRecord record = RegistrationRecord.fromBytes(registrationRecord,
        oprf.getOPRFSerializationSize(), hashFunctions.getHashSize(), keyDerivation.getNonceSize());
    KE1 ke1 =
        KE1.fromBytes(ke1Bytes, oprf.getOPRFSerializationSize(), keyDerivation.getNonceSize());
    CredentialResponse credentialResponse =
        createCredentialResponse(ke1.credentialRequest(), serverPublicKey, record,
            credentialIdentifier, oprfSeed);
    CleartextCredentials cleartextCredentials =
        OpaqueUtils.createCleartextCredentials(serverPublicKey,
            record.clientPublicKey(), serverIdentity, clientIdentity);
    AuthResponse authResponse;
    try {
      authResponse =
          authServerRespond(cleartextCredentials, serverPrivateKey, record.clientPublicKey(), ke1,
              credentialResponse, state);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException
        | NoSuchProviderException e) {
      log.error("Diffie Hellman private key operation failed");
      // These are all configuration errors. Hard fail.
      throw new RuntimeException(e);
    }
    return new KE2(credentialResponse, authResponse);
  }

  /** {@inheritDoc}. */
  @Override
  public byte[] serverFinish(byte[] ke3Bytes, ServerState state)
      throws ClientAuthenticationException {
    log.debug("OPAQUE server finish");
    KE3 ke3 = KE3.fromBytes(ke3Bytes);
    return authServerFinalize(ke3, state);
  }

  /**
   * Finalizes the server authentication process by verifying the client's message authentication
   * code (MAC) and returning the established session key.
   *
   * @param ke3 the third key exchange message containing the client's MAC.
   * @param state the current server state, including the expected client MAC and session key.
   * @return the session key derived during the key exchange process.
   * @throws ClientAuthenticationException if the client's MAC does not match the server's expected
   *         value, indicating a failed client authentication
   */
  protected byte[] authServerFinalize(KE3 ke3, ServerState state)
      throws ClientAuthenticationException {
    if (!Arrays.equals(ke3.clientMac(), state.getAkeState().getExpectedClientMac())) {
      throw new ClientAuthenticationException("Client authentication failed - Client mac mismatch");
    }
    return state.getAkeState().getSessionKey();
  }

  /**
   * Creates a CredentialResponse object by combining the evaluated message, masking nonce, and
   * masked response, which are derived from the provided input parameters.
   *
   * @param request the CredentialRequest containing the blinded message used for evaluating the
   *        response.
   * @param serverPublicKey the server's public key used in constructing the masked response.
   * @param record the RegistrationRecord containing the client's public key, masking key, and
   *        envelope.
   * @param credentialIdentifier a unique identifier for the credential being processed.
   * @param oprfSeed a seed value used for key derivation and blinding during the OPRF process.
   * @return a CredentialResponse object containing the evaluated message, masking nonce, and masked
   *         response.
   * @throws DeriveKeyPairErrorException if there is an error while deriving a key pair during the
   *         OPRF evaluation.
   * @throws DeserializationException if there is an error deserializing input data during
   *         processing.
   * @throws InvalidInputException if any provided input data is found to be invalid.
   */
  protected CredentialResponse createCredentialResponse(CredentialRequest request,
      byte[] serverPublicKey,
      RegistrationRecord record, byte[] credentialIdentifier, byte[] oprfSeed)
      throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException {

    byte[] evaluatedMessage =
        getEvaluateMessage(request.blindedMessage(), oprfSeed, credentialIdentifier);
    byte[] maskingNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] credentialResponsePad = keyDerivation.expand(record.maskingKey(),
        OpaqueUtils.concat(maskingNonce, "CredentialResponsePad"),
        keyDerivation.getNonceSize() + hashFunctions.getMacSize() + serverPublicKey.length);
    byte[] maskedResponse = OpaqueUtils.xor(credentialResponsePad,
        OpaqueUtils.concat(serverPublicKey, record.envelope().getEncoded()));
    return new CredentialResponse(evaluatedMessage, maskingNonce, maskedResponse);
  }

  /**
   * Evaluates a blinded message using the OPRF (Oblivious Pseudorandom Function) protocol and
   * returns the serialized result. The evaluation involves deriving a key pair from the provided
   * seed and credential identifier, and then performing blind evaluation using the appropriate
   * private key. If a static OPRF key pair is available, it is used in combination to finalize the
   * evaluation.
   *
   * @param blindedMessage the blinded message provided by the client to be evaluated.
   * @param oprfSeed the seed used for key derivation within the OPRF protocol.
   * @param credentialIdentifier a unique credential identifier used for key derivation.
   * @return the serialized evaluated element resulting from the OPRF protocol.
   * @throws DeriveKeyPairErrorException if an error occurs during key pair derivation.
   * @throws DeserializationException if an error occurs while deserializing elements
   */
  protected byte[] getEvaluateMessage(byte[] blindedMessage, byte[] oprfSeed,
      byte[] credentialIdentifier)
      throws DeriveKeyPairErrorException, DeserializationException {
    byte[] seed = keyDerivation.expand(oprfSeed,
        OpaqueUtils.concat(credentialIdentifier, "OprfKey"), oprf.getOprfPrivateKeySize());
    KeyPairRecord keyPair = oprf.deriveKeyPair(seed, "OPAQUE-DeriveKeyPair");
    ECPoint blindedElement = oprf.deserializeElement(blindedMessage);
    ECPoint evaluatedElement =
        oprf.blindEvaluate(new OprfPrivateKey(keyPair.privateKey()), blindedElement);
    if (staticOprfKeyPair == null) {
      log.debug(
          "No static (HSM) OPRF key pair configured. No further actions on the evaluated element.");
      return oprf.serializeElement(evaluatedElement);
    }
    log.debug("Using static (HSM) OPRF key pair to finalize the evaluated element.");
    ECPoint staticKeyEvaluated =
        oprf.blindEvaluate(new OprfPrivateKey(staticOprfKeyPair), evaluatedElement);
    return oprf.serializeElement(staticKeyEvaluated);
  }

  /**
   * Responds to the client's authentication request during the OPAQUE protocol by deriving shared
   * secrets and constructing the authentication response. This process involves generating nonces,
   * performing Diffie-Hellman operations, deriving shared keys, and computing message
   * authentication codes (MACs).
   *
   * @param cleartextCredentials the cleartext credentials containing the server's public key,
   *        server identity, and client identity.
   * @param serverPrivateKey the server's private key used for the Diffie-Hellman operations.
   * @param clientPublicKey the client's public key used in the authentication.
   * @param ke1 the first key exchange message from the client, containing the authentication
   *        request and credential request.
   * @param credentialResponse the credential response generated as part of the OPRF protocol,
   *        including the evaluated message, masking nonce, and masked response.
   * @param state the current state of the server, used to track the authentication and session key
   *        negotiation process.
   * @return an AuthResponse object containing the server nonce, server public key share, and the
   *         computed server MAC to be sent to the client.
   * @throws DeriveKeyPairErrorException if an error occurs during Diffie-Hellman key pair
   *         derivation.
   * @throws InvalidInputException if any of the input data is invalid or improperly formatted.
   * @throws DeserializationException if an error occurs while deserializing protocol elements.
   * @throws NoSuchAlgorithmException if a required cryptographic algorithm is unavailable.
   * @throws InvalidKeySpecException if the key specification is invalid during key handling.
   * @throws InvalidKeyException if a key is invalid for cryptographic operations.
   * @throws NoSuchProviderException if a required cryptographic provider is unavailable
   */
  protected AuthResponse authServerRespond(CleartextCredentials cleartextCredentials,
      OprfPrivateKey serverPrivateKey, byte[] clientPublicKey, KE1 ke1,
      CredentialResponse credentialResponse, ServerState state)
      throws DeriveKeyPairErrorException, InvalidInputException, DeserializationException,
      NoSuchAlgorithmException,
      InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

    byte[] serverNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] serverKeyShareSeed = OpaqueUtils.random(keyDerivation.getSeedSize());
    KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(serverKeyShareSeed);

    // Derive shared secrets
    byte[] dh1 = oprf.diffieHellman(new OprfPrivateKey(keyPair.privateKey()),
        ke1.authRequest().clientPublicKey());
    byte[] dh2 = oprf.diffieHellman(serverPrivateKey, ke1.authRequest().clientPublicKey());
    byte[] dh3 = oprf.diffieHellman(new OprfPrivateKey(keyPair.privateKey()), clientPublicKey);
    byte[] ikm = OpaqueUtils.concat(dh1, dh2, dh3);

    // Derive shared key
    byte[] preamble = OpaqueUtils.preamble(cleartextCredentials.clientIdentity(),
        ke1, cleartextCredentials.serverIdentity(),
        credentialResponse, serverNonce, keyPair.publicKey(), oprf.getContext());
    DerivedKeys derivedKeys = keyDerivation.deriveKeys(ikm, preamble);
    byte[] serverMac = hashFunctions.mac(derivedKeys.km2(), hashFunctions.hash(preamble));
    state.getAkeState().setExpectedClientMac(hashFunctions.mac(derivedKeys.km3(),
        hashFunctions.hash(OpaqueUtils.concat(preamble, serverMac))));
    state.getAkeState().setSessionKey(derivedKeys.sessionKey());
    return new AuthResponse(serverNonce, keyPair.publicKey(), serverMac);
  }

}
