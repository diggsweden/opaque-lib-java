// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.opaque.client.BlindedElement;
import se.digg.crypto.opaque.client.CleartextCredentials;
import se.digg.crypto.opaque.client.ClientAkeState;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.ClientStoreRecord;
import se.digg.crypto.opaque.client.CredentialRequestData;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.client.impl.DefaultOpaqueClient;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.crypto.StretchAlgorithm;
import se.digg.crypto.opaque.crypto.impl.ArgonStretch;
import se.digg.crypto.opaque.crypto.impl.DefaultOpaqueCurve;
import se.digg.crypto.opaque.crypto.impl.DefaultOprfFunction;
import se.digg.crypto.opaque.crypto.impl.HKDFKeyDerivation;
import se.digg.crypto.opaque.dto.AuthRequest;
import se.digg.crypto.opaque.dto.AuthResponse;
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
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.crypto.opaque.server.impl.DefaultOpaqueServer;
import se.digg.crypto.opaque.server.keys.DerivedKeys;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;
import se.digg.crypto.opaque.testdata.OPRFTestVectorData;
import se.digg.crypto.opaque.testdata.OpaqueTestVectorData;
import se.digg.crypto.opaque.testdata.TestData;
import se.digg.crypto.opaque.utils.TU;

/**
 * Testing RFC test vectors
 */
@Slf4j
public class TestVectorTests {

  static List<OPRFTestVectorData> oprfTestVectorData;

  static List<OpaqueTestVectorData> opaqueTestVectors;

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    oprfTestVectorData = TestData.getOprfTestVectors();
    opaqueTestVectors = TestData.getOpaqueTestVectors();
  }

  @Test
  void opaqueCurveTest() throws Exception {
    log.info("Testing P-256");
    testOpaqueCurve(new DefaultOpaqueCurve(
      ECNamedCurveTable.getParameterSpec("P-256"),
      HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_,
      new DstContext(DstContext.IDENTIFIER_P256_SHA256)));
    log.info("Testing P-384");
    testOpaqueCurve(new DefaultOpaqueCurve(
      ECNamedCurveTable.getParameterSpec("P-384"),
      HashToCurveProfile.P384_XMD_SHA_384_SSWU_RO_,
      new DstContext(DstContext.IDENTIFIER_P384_SHA384)));
    log.info("Testing P-521");
    testOpaqueCurve(new DefaultOpaqueCurve(
      ECNamedCurveTable.getParameterSpec("P-521"),
      HashToCurveProfile.P521_XMD_SHA_512_SSWU_RO_,
      new DstContext(DstContext.IDENTIFIER_P521_SHA512)));
  }
  void testOpaqueCurve(OpaqueCurve opaqueCurve) throws Exception {

    log.info("Hash2Curve :'' -> {}", Hex.toHexString(opaqueCurve.hashToGroup("".getBytes()).getEncoded(true)));
    log.info("Hash2Curve :'Test' -> {}", Hex.toHexString(opaqueCurve.hashToGroup("Test".getBytes()).getEncoded(true)));
    log.info("Hash2Curve :'Domain' -> {}", Hex.toHexString(opaqueCurve.hashToGroup("Domain".getBytes()).getEncoded(true)));

    log.info("Hash2Scalar :'' -> {}", opaqueCurve.hashToScalar("".getBytes()).toString(16));
    log.info("Hash2Scalar :'Test' -> {}", opaqueCurve.hashToScalar("Test".getBytes()).toString(16));
    log.info("Hash2Scalar (Domain dst) :'Domain' -> {}", opaqueCurve.hashToScalar("Domain".getBytes(), "Domain").toString(16));
  }

  @Test
  void testVectorTests() throws Exception{
    List<Integer> testIndexList = List.of(4,5);
    for (Integer index : testIndexList) {
      performTestVectorTest(index);
    }
  }

  void performTestVectorTest(int vectorIndex) throws Exception {

    OpaqueTestVectorData testVectors = opaqueTestVectors.get(vectorIndex);
    log.info("TestVector 6 - P256-SHA256\n {}", TestData.jsonPrettyPrinter().writeValueAsString(testVectors));

    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
    StretchAlgorithm stretchAlgorithm = new ArgonStretch(ArgonStretch.ARGON_PROFILE_IDENTITY);
    HashFunctions hashFunctions = new HashFunctions(new SHA256Digest(), stretchAlgorithm);
    OpaqueCurve opaqueCurve = new DefaultOpaqueCurve(ECNamedCurveTable.getParameterSpec("P-256"), HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_, new DstContext(DstContext.IDENTIFIER_P256_SHA256));
    KeyDerivationFunctions keyDerivationFunctions = new HKDFKeyDerivation(hashFunctions);
    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve, hashFunctions, "OPAQUE-POC");
    TestOpaqueClient opaqueClient = new TestOpaqueClient(oprf, keyDerivationFunctions, hashFunctions);
    TestOpaqueServer opaqueServer = new TestOpaqueServer(oprf, keyDerivationFunctions, hashFunctions);

    // Setup test values
    byte[] password = Optional.ofNullable(h(testVectors.getInputs().getPassword())).orElse(OpaqueUtils.random(8));

    opaqueClient.setNextBlind(h(testVectors.getInputs().getBlindRegistration()));

    RegistrationRequestResult registrationRequestResult = opaqueClient.createRegistrationRequest(password);

    RegistrationResponse testRegistrationResponse = opaqueServer.createRegistrationResponse(
      registrationRequestResult.registrationRequest().getEncoded(),
      h(testVectors.getInputs().getServerPublicKey()),
      h(testVectors.getInputs().getCredentialIdentifier()),
      h(testVectors.getInputs().getOprfSeed()));

    // Inject envelopeNonce in test client
    opaqueClient.setNextEnvelopeNonce(
      h(testVectors.getInputs().getEnvelopeNonce()));

    RegistrationFinalizationResult registrationFinalizationResult = opaqueClient.finalizeRegistrationRequest(
      password,
      registrationRequestResult.blind(),
      testRegistrationResponse.getEncoded(),
      h(testVectors.getInputs().getServerIdentity()),
      h(testVectors.getInputs().getClientIdentity()));

    RegistrationRecord registrationRecord = registrationFinalizationResult.registrationRecord();
    Envelope envelope = registrationRecord.envelope();
    log.info(TU.hex("Client public key", registrationRecord.clientPublicKey()));
    log.info(TU.hex("Envelope nonce", envelope.nonce()));
    log.info(TU.hex("Auth tag", envelope.authTag()));
    log.info(TU.hex("Export key", registrationFinalizationResult.exportKey()));
    log.info(TU.hex("Registration upload", registrationFinalizationResult.registrationRecord().getEncoded()));

    if (h(testVectors.getOutputs().getRegistrationUpload()) != null) {
      assertArrayEquals(h(testVectors.getOutputs().getRegistrationUpload()), registrationFinalizationResult.registrationRecord().getEncoded());
    }


    // Auth process

    ClientState clientState = new ClientState();
    opaqueClient.setNextBlind(h(testVectors.getInputs().getBlindLogin()));
    opaqueClient.setNextClientNonce(h(testVectors.getInputs().getClientNonce()));
    opaqueClient.setNextClientKeyshareSeed(h(testVectors.getInputs().getClientKeyshareSeed()));
    KE1 ke1 = opaqueClient.generateKe1(
      password,
      clientState
    );
    log.info(TU.hex("KE1", ke1.getEncoded()));
    if (h(testVectors.getOutputs().getKe1()) != null) {
      assertArrayEquals(h(testVectors.getOutputs().getKe1()), ke1.getEncoded());
    }

    // Prepare for ke2
    ServerState serverState = new ServerState();
    OprfPrivateKey serverPrivateKey = new OprfPrivateKey(h(testVectors.getInputs().getServerPrivateKey()));
    opaqueServer.setNextServerNonce(h(testVectors.getInputs().getServerNonce()));
    opaqueServer.setNextMaskingNonce(h(testVectors.getInputs().getMaskingNonce()));
    opaqueServer.setNextServerKeyShareSeed(h(testVectors.getInputs().getServerKeyshareSeed()));

    KE2 ke2 = opaqueServer.generateKe2(
      h(testVectors.getInputs().getServerIdentity()), serverPrivateKey,
      h(testVectors.getInputs().getServerPublicKey()),
      registrationRecord.getEncoded(),
      h(testVectors.getInputs().getCredentialIdentifier()),
      h(testVectors.getInputs().getOprfSeed()), ke1.getEncoded(),
      h(testVectors.getInputs().getClientIdentity()), serverState
    );
    log.info(TU.hex("KE2", ke2.getEncoded()));
    AuthResponse authResponse = ke2.authResponse();
    log.info(TU.hex("ServerPublicKeyShare", authResponse.serverPublicKeyShare()));
    log.info(TU.hex("Server Mac", authResponse.serverMac()));
    CredentialResponse credentialResponse = ke2.credentialResponse();
    log.info(TU.hex("Masked response", credentialResponse.maskedResponse()));
    log.info(TU.hex("Evaluated message", credentialResponse.evaluatedMessage()));

    KE2 tvKe2 = KE2.fromBytes(h(testVectors.getOutputs().getKe2()), keyDerivationFunctions.getNonceSize(), hashFunctions.getMacSize(), opaqueCurve.getElementSerializationSize());
    assertArrayEquals(tvKe2.getEncoded(), ke2.getEncoded());

    ClientKeyExchangeResult clientKeyExchangeResult = opaqueClient.generateKe3(
      h(testVectors.getInputs().getClientIdentity()),
      h(testVectors.getInputs().getServerIdentity()),
      ke2.getEncoded(), clientState
    );
    KE3 ke3 = clientKeyExchangeResult.ke3();
    log.info(TU.hex("KE3 (client mac)", ke3.getEncoded()));
    log.info(TU.hex("Session key", clientKeyExchangeResult.sessionKey()));
    log.info(TU.hex("Auth key", clientKeyExchangeResult.exportKey()));

    if (testVectors.getOutputs().getKe3() != null) {
      assertArrayEquals(h(testVectors.getOutputs().getKe3()), ke3.getEncoded());
      assertArrayEquals(h(testVectors.getOutputs().getSessionKey()), clientKeyExchangeResult.sessionKey());
      assertArrayEquals(h(testVectors.getOutputs().getExportKey()), clientKeyExchangeResult.exportKey());
    }


    log.info("Test vectors match");
  }

  public static byte[] h(String hexString){
    if (hexString == null) {
      return null;
    }
    return Hex.decode(hexString);
  }

  @Test
  void oprfTest() throws Exception {


    OPRFTestVectorData p256VectorMode0 = oprfTestVectorData.get(6);
    log.info("TestVector - P256-SHA256 - Mode 0\n {}", TestData.jsonPrettyPrinter().writeValueAsString(p256VectorMode0));

    DstContext dstContext = new DstContext(DstContext.IDENTIFIER_P256_SHA256);
    log.info("Context-String: {}", new String(dstContext.getContextString()));
    log.info("Hash-to-group dst: {}", new String(dstContext.getHash2CurveDST()));
    log.info("Key derivation dst: {}", new String(dstContext.getDomainSeparationTag("DeriveKeyPair")));

    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
    StretchAlgorithm stretchAlgorithm = new ArgonStretch(ArgonStretch.ARGON_PROFILE_IDENTITY);
    HashFunctions hashFunctions = new HashFunctions(new SHA256Digest(), stretchAlgorithm);
    OpaqueCurve opaqueCurve = new DefaultOpaqueCurve(ECNamedCurveTable.getParameterSpec("P-256"), HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_, new DstContext(DstContext.IDENTIFIER_P256_SHA256));
    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve, hashFunctions, "Demo");

    //Batch 1
    OPRFTestVectorData.OPRFTestVectors b1v = p256VectorMode0.getVectors().get(0);
    // Generate blind
    ECPoint pwPoint = opaqueCurve.hashToGroup(Hex.decode(b1v.getInput()));
    BigInteger blind = new BigInteger(1, Hex.decode(b1v.getBlind()));
    ECPoint blinded = pwPoint.multiply(blind);
    log.info("Blinded point: {}", Hex.toHexString(blinded.getEncoded(true)));

    // Derive the OPRF private key
    byte[] oprfSeed = Hex.decode(p256VectorMode0.getSeed());
    byte[] keyInfo = Hex.decode(p256VectorMode0.getKeyInfo());
    KeyPairRecord keyPairRecord = oprf.deriveKeyPair(oprfSeed, new String(keyInfo));

    log.info("Derived scalar: {}", Hex.toHexString(keyPairRecord.privateKey()));
    log.info("Derived public key: {}", Hex.toHexString(keyPairRecord.publicKey()));

  }


  @Setter public static class TestOpaqueServer extends DefaultOpaqueServer {

    byte[] nextMaskingNonce;
    byte[] nextServerNonce;
    byte[] nextServerKeyShareSeed;

    public TestOpaqueServer(OprfFunctions oprf, KeyDerivationFunctions keyDerivation, HashFunctions hashFunctions) {
      super(oprf, keyDerivation, hashFunctions);
    }

    byte[] getMaskingNonce() {
      if (nextMaskingNonce != null) {
        byte[] returnValue = Arrays.clone(nextMaskingNonce);
        nextMaskingNonce = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getNonceSize());
      }
    }
    byte[] getServerNonce() {
      if (nextServerNonce != null) {
        byte[] returnValue = Arrays.clone(nextServerNonce);
        nextServerNonce = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getNonceSize());
      }
    }
    byte[] getServerKeyShareSeed() {
      if (nextServerKeyShareSeed != null) {
        byte[] returnValue = Arrays.clone(nextServerKeyShareSeed);
        nextServerKeyShareSeed = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getSeedSize());
      }
    }



    @Override
    protected CredentialResponse createCredentialResponse(CredentialRequest request, byte[] serverPublicKey,
      RegistrationRecord record, byte[] credentialIdentifier, byte[] oprfSeed)
      throws DeriveKeyPairErrorException, DeserializationException, InvalidInputException {

      byte[] evaluatedMessage = getEvaluateMessage(request.blindedMessage(), oprfSeed, credentialIdentifier);
      byte[] maskingNonce = getMaskingNonce();
      byte[] credentialResponsePad = keyDerivation.expand(record.maskingKey(),
        OpaqueUtils.concat(maskingNonce, "CredentialResponsePad"),
        keyDerivation.getNonceSize() + hashFunctions.getMacSize() + serverPublicKey.length);
      byte[] maskedResponse = OpaqueUtils.xor(credentialResponsePad, OpaqueUtils.concat(serverPublicKey, record.envelope().getEncoded()));
      return new CredentialResponse(evaluatedMessage, maskingNonce, maskedResponse);
    }

    @Override
    protected AuthResponse authServerRespond(CleartextCredentials cleartextCredentials, OprfPrivateKey serverPrivateKey, byte[] clientPublicKey, KE1 ke1, CredentialResponse credentialResponse, ServerState state)
      throws DeriveKeyPairErrorException, InvalidInputException, DeserializationException, NoSuchAlgorithmException,
      InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

      byte[] serverNonce = getServerNonce();
      byte[] serverKeyShareSeed = getServerKeyShareSeed();
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

  @Setter public static class TestOpaqueClient extends DefaultOpaqueClient {

    byte[] nextEnvelopeNonce = null;
    byte[] nextBlind;
    byte[] nextClientNonce;
    byte[] nextClientKeyshareSeed;

    public TestOpaqueClient(OprfFunctions oprf, KeyDerivationFunctions keyDerivation, HashFunctions hashFunctions) {
      super(oprf, keyDerivation, hashFunctions);
    }

    @Override
    protected ClientStoreRecord store(byte[] randomizedPassword, byte[] serverPublicKey, byte[] serverIdentity,
      byte[] clientIdentity) throws DeriveKeyPairErrorException, InvalidInputException {
      byte[] envelopeNonce = getEnvelopeNonce();
      byte[] maskingKey = keyDerivation.expand(randomizedPassword, "MaskingKey", hashFunctions.getHashSize());
      byte[] authKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelopeNonce, "AuthKey"  ), hashFunctions.getHashSize());
      byte[] exportKey = keyDerivation.expand(randomizedPassword,
        OpaqueUtils.concat(envelopeNonce, "ExportKey"), hashFunctions.getHashSize());
      byte[] seed = keyDerivation.expand(randomizedPassword, OpaqueUtils.concat(envelopeNonce, "PrivateKey"),
        keyDerivation.getSeedSize());
      KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(seed);
      byte[] clientPublicKey = keyPair.publicKey();
      CleartextCredentials cleartextCredentials = OpaqueUtils.createCleartextCredentials(
        serverPublicKey, clientPublicKey, serverIdentity, clientIdentity);

      byte[] authTag = hashFunctions.mac(authKey, OpaqueUtils.concat(envelopeNonce, cleartextCredentials.serialize()));
      Envelope envelope = new Envelope(envelopeNonce, authTag);
      return new ClientStoreRecord(envelope, clientPublicKey, maskingKey, exportKey);
    }

    @Override public RegistrationRequestResult createRegistrationRequest(byte[] password)
      throws DeriveKeyPairErrorException {
      BlindedElement blindData = blind(password, getBlind(), oprf.getCurve());
      byte[] blindedMessage = oprf.serializeElement(blindData.blindElement());
      RegistrationRequest request = new RegistrationRequest(blindedMessage);
      return new RegistrationRequestResult(request, blindData.blind());
    }

    @Override
    protected CredentialRequestData createCredentialRequest(byte[] password) throws DeriveKeyPairErrorException {
      BlindedElement blindData = blind(password, getBlind(), oprf.getCurve());
      byte[] blindedMessage = oprf.serializeElement(blindData.blindElement());
      CredentialRequest credentialRequest = new CredentialRequest(blindedMessage);
      return new CredentialRequestData(credentialRequest, blindData.blind());
    }

    static BlindedElement blind(byte[] password, byte[] blind, OpaqueCurve curve) {
      ECPoint passwordPoint = curve.hashToGroup(password);
      ECPoint blindedElement = passwordPoint.multiply(new BigInteger(1, blind));
      return new BlindedElement(blind, blindedElement);
    }


    protected KE1 authClientStart(CredentialRequest credentialRequest, ClientAkeState akeState) throws DeriveKeyPairErrorException {
      byte[] clientNonce = getClientNonce();
      byte[] clientKeyshareSeed = getClientKeyshareSeed();
      KeyPairRecord keyPair = oprf.deriveDiffieHellmanKeyPair(clientKeyshareSeed);
      AuthRequest authRequest = new AuthRequest(clientNonce, keyPair.publicKey());
      KE1 ke1 = new KE1(credentialRequest, authRequest);
      akeState.setClientSecret(keyPair.privateKey());
      akeState.setKe1(ke1);
      return ke1;
    }


    byte[] getEnvelopeNonce() {
      if (nextEnvelopeNonce != null) {
        byte[] returnValue = Arrays.clone(nextEnvelopeNonce);
        nextEnvelopeNonce = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getNonceSize());
      }
    }

    byte[] getBlind() {
      if (nextBlind != null) {
        byte[] returnValue = Arrays.clone(nextBlind);
        nextBlind = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getNonceSize());
      }
    }

    byte[] getClientNonce() {
      if (nextClientNonce != null) {
        byte[] returnValue = Arrays.clone(nextClientNonce);
        nextClientNonce = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getNonceSize());
      }
    }

    byte[] getClientKeyshareSeed() {
      if (nextClientKeyshareSeed != null) {
        byte[] returnValue = Arrays.clone(nextClientKeyshareSeed);
        nextClientKeyshareSeed = null;
        return returnValue;
      } else {
        return OpaqueUtils.random(keyDerivation.getSeedSize());
      }
    }


  }

}
