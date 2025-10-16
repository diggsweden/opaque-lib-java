package se.digg.crypto.opaque.server.impl;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
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
 * Default implementation of OPAQUE server
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultOpaqueServer implements OpaqueServer {

  /** The server HSM protected private key */
  @Setter protected KeyPair staticOprfKeyPair;

  protected final OprfFunctions oprf;
  protected final KeyDerivationFunctions keyDerivation;
  protected final HashFunctions hashFunctions;

  @Override public RegistrationResponse createRegistrationResponse(byte[] registrationRequest,
    byte[] serverPublicKey ,byte[] credentialIdentifier, byte[] oprfSeed) throws DeserializationException,
    DeriveKeyPairErrorException {
    RegistrationRequest request = RegistrationRequest.fromBytes(registrationRequest);

    byte[] evaluatedMessage = getEvaluateMessage(request.blindedMessage(), oprfSeed, credentialIdentifier);
    return new RegistrationResponse(evaluatedMessage, serverPublicKey);
  }

  @Override public KE2 generateKe2(byte[] serverIdentity, OprfPrivateKey serverPrivateKey, byte[] serverPublicKey,
    byte[] registrationRecord, byte[] credentialIdentifier, byte[] oprfSeed, byte[] ke1Bytes, byte[] clientIdentity, ServerState state)
    throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException {
    RegistrationRecord record = RegistrationRecord.fromBytes(registrationRecord, oprf.getOPRFSerializationSize(), hashFunctions.getHashSize(), keyDerivation.getNonceSize());
    KE1 ke1 = KE1.fromBytes(ke1Bytes, oprf.getOPRFSerializationSize(), keyDerivation.getNonceSize());
    CredentialResponse credentialResponse = createCredentialResponse(ke1.credentialRequest(), serverPublicKey, record,
      credentialIdentifier, oprfSeed);
    CleartextCredentials cleartextCredentials = OpaqueUtils.createCleartextCredentials(serverPublicKey,
      record.clientPublicKey(), serverIdentity, clientIdentity);
    AuthResponse authResponse;
    try {
      authResponse = authServerRespond(cleartextCredentials, serverPrivateKey, record.clientPublicKey(), ke1,
        credentialResponse, state);
    }
    catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException e) {
      log.error("Diffie Hellman private key operation failed");
      // These are all configuration errors. Hard fail.
      throw new RuntimeException(e);
    }
    return new KE2(credentialResponse, authResponse);
  }

  @Override public byte[] serverFinish(byte[] ke3Bytes, ServerState state) throws ClientAuthenticationException {
    KE3 ke3 = KE3.fromBytes(ke3Bytes);
    return authServerFinalize(ke3, state);
  }

  protected byte[] authServerFinalize(KE3 ke3, ServerState state) throws ClientAuthenticationException {
    if (!Arrays.equals(ke3.clientMac(), state.getAkeState().getExpectedClientMac())) {
      throw new ClientAuthenticationException("Client authentication failed - Client mac mismatch");
    }
    return state.getAkeState().getSessionKey();
  }

  protected CredentialResponse createCredentialResponse(CredentialRequest request, byte[] serverPublicKey,
    RegistrationRecord record, byte[] credentialIdentifier, byte[] oprfSeed)
    throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException {

    byte[] evaluatedMessage = getEvaluateMessage(request.blindedMessage(), oprfSeed, credentialIdentifier);
    byte[] maskingNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] credentialResponsePad = keyDerivation.expand(record.maskingKey(),
      OpaqueUtils.concat(maskingNonce, "CredentialResponsePad"),
      keyDerivation.getNonceSize() + hashFunctions.getMacSize() + serverPublicKey.length);
    byte[] maskedResponse = OpaqueUtils.xor(credentialResponsePad, OpaqueUtils.concat(serverPublicKey, record.envelope().getEncoded()));
    return new CredentialResponse(evaluatedMessage, maskingNonce, maskedResponse);
  }

  protected byte[] getEvaluateMessage(byte[] blindedMessage, byte[] oprfSeed, byte[] credentialIdentifier)
    throws DeriveKeyPairErrorException, DeserializationException {
    byte[] seed = keyDerivation.expand(oprfSeed, OpaqueUtils.concat(credentialIdentifier, "OprfKey"), oprf.getOprfPrivateKeySize());
    KeyPairRecord keyPair = oprf.deriveKeyPair(seed, "OPAQUE-DeriveKeyPair");
    ECPoint blindedElement = oprf.deserializeElement(blindedMessage);
    ECPoint evaluatedElement = oprf.blindEvaluate(new OprfPrivateKey(keyPair.privateKey()), blindedElement);
    if (staticOprfKeyPair == null) {
      return oprf.serializeElement(evaluatedElement);
    }
    ECPoint staticKeyEvaluated = oprf.blindEvaluate(new OprfPrivateKey(staticOprfKeyPair), evaluatedElement);
    return oprf.serializeElement(staticKeyEvaluated);
  }

  protected AuthResponse authServerRespond(CleartextCredentials cleartextCredentials, OprfPrivateKey serverPrivateKey, byte[] clientPublicKey, KE1 ke1, CredentialResponse credentialResponse, ServerState state)
    throws DeriveKeyPairErrorException, InvalidInputException, DeserializationException, NoSuchAlgorithmException,
    InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

    byte[] serverNonce = OpaqueUtils.random(keyDerivation.getNonceSize());
    byte[] serverKeyShareSeed = OpaqueUtils.random(keyDerivation.getSeedSize());
    KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(serverKeyShareSeed);

    // Derive shared secrets
    byte[] dh1 = oprf.diffieHellman(new OprfPrivateKey(keyPair.privateKey()), ke1.authRequest().clientPublicKey());
    byte[] dh2 = oprf.diffieHellman(serverPrivateKey, ke1.authRequest().clientPublicKey());
    byte[] dh3 = oprf.diffieHellman(new OprfPrivateKey(keyPair.privateKey()), clientPublicKey);
    byte[] ikm = OpaqueUtils.concat(dh1, dh2, dh3);

    // Derive shared key
    byte[] preamble = OpaqueUtils.preamble(cleartextCredentials.clientIdentity(),
      ke1, cleartextCredentials.serverIdentity(),
      credentialResponse, serverNonce, keyPair.publicKey(), oprf.getContext());
    DerivedKeys derivedKeys = keyDerivation.deriveKeys(ikm, preamble);
    byte[] serverMac = hashFunctions.mac(derivedKeys.km2(), hashFunctions.hash(preamble));
    state.getAkeState().setExpectedClientMac(hashFunctions.mac(derivedKeys.km3(), hashFunctions.hash(OpaqueUtils.concat(preamble, serverMac))));
    state.getAkeState().setSessionKey(derivedKeys.sessionKey());
    return new AuthResponse(serverNonce, keyPair.publicKey(), serverMac);
  }

}
