// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Optional;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.client.impl.DefaultOpaqueClient;
import se.digg.crypto.opaque.crypto.DstContext;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.crypto.KeyDerivationFunctions;
import se.digg.crypto.opaque.crypto.OpaqueCurve;
import se.digg.crypto.opaque.crypto.OprfFunctions;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.crypto.impl.ArgonStretch;
import se.digg.crypto.opaque.crypto.impl.DefaultOpaqueCurve;
import se.digg.crypto.opaque.crypto.impl.DefaultOprfFunction;
import se.digg.crypto.opaque.crypto.impl.HKDFKeyDerivation;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE2;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.server.OpaqueServer;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.crypto.opaque.server.impl.DefaultOpaqueServer;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;
import se.digg.crypto.opaque.testimpl.MockGenericOpaqueCurve;
import se.digg.crypto.opaque.utils.SLB;
import se.digg.crypto.opaque.utils.TU;

/**
 * Basic test of OPAQUE
 */
@Slf4j
class OpaqueBasicTest {

  static HashFunctions sha256hash;
  static HashFunctions sha256Identity;
  static OpaqueCurve p256Curve;
  static OprfFunctions oprfP256;
  static KeyDerivationFunctions hkdfKeyDerivation;

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
    sha256hash = new HashFunctions(SHA256Digest.newInstance(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    sha256Identity = new HashFunctions(SHA256Digest.newInstance(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_IDENTITY));
    hkdfKeyDerivation = new HKDFKeyDerivation(sha256hash);
    p256Curve = new DefaultOpaqueCurve(ECNamedCurveTable.getParameterSpec("P-256"), HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_, new DstContext(DstContext.IDENTIFIER_P256_SHA256));
    oprfP256 = new DefaultOprfFunction(p256Curve, sha256hash, "OPAQUE-POC");
  }

  @Test
  void basicAuthTest() throws Exception {
    log.info("Basic Opaque test");
    OpaqueClient client = new DefaultOpaqueClient(oprfP256, hkdfKeyDerivation, sha256hash);
    OpaqueServer server = new DefaultOpaqueServer(oprfP256, hkdfKeyDerivation, sha256hash);
    String password = "650132";
    byte[] oprfSeed = OpaqueUtils.random(64);
    KeyPairRecord serverKeyPair = oprfP256.deriveKeyPair(OpaqueUtils.random(64), "serverKeyPair");
    performTest("Basic test with random key and seed", client, server, oprfSeed, password, serverKeyPair, oprfP256.getContext());
  }
  @Test
  void p256TestVectorTest() throws Exception {
    log.info("Basic Opaque test");
    OpaqueClient client = new DefaultOpaqueClient(oprfP256, hkdfKeyDerivation, sha256Identity);
    OpaqueServer server = new DefaultOpaqueServer(oprfP256, hkdfKeyDerivation, sha256Identity);

    String password = "650132";
    byte[] oprfSeed = Hex.decode("bb1cd59e16ac09bc0cb6d528541695d7eba2239b1613a3db3ade77b36280f725");
    KeyPairRecord serverKeyPair = new KeyPairRecord(
      Hex.decode("0221e034c0e202fe883dcfc96802a7624166fed4cfcab4ae30cf5f3290d01c88bf"),
      Hex.decode("34fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a5888c7")
    );
    performTest("Basic test with preset server keys", client, server, oprfSeed, password, serverKeyPair, oprfP256.getContext());
  }

  @Test
  void sha512Test() throws Exception {
    log.info("SHA-512 Opaque test");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OprfFunctions oprf = new DefaultOprfFunction(p256Curve, hashFunctions, "SHA-256-Test");
    KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);
    OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);
    OpaqueServer server = new DefaultOpaqueServer(oprf, hkdf, hashFunctions);
    String password = "650132";
    byte[] oprfSeed = Hex.decode("bb1cd59e16ac09bc0cb6d528541695d7eba2239b1613a3db3ade77b36280f725");
    KeyPairRecord serverKeyPair = new KeyPairRecord(
      Hex.decode("0221e034c0e202fe883dcfc96802a7624166fed4cfcab4ae30cf5f3290d01c88bf"),
      Hex.decode("34fbe7e830be1fe8d2187c97414e3826040cbe49b893b64229bab5e85a5888c7")
    );
    performTest("SHA-512 Opaque test", client, server, oprfSeed, password, serverKeyPair, oprfP256.getContext());
  }

  @Test
  void otherEccCurvesTest() throws Exception {
    log.info("25519 curve test");
    ECNamedCurveParameterSpec curve25519 = ECNamedCurveTable.getParameterSpec("curve25519");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve opaqueCurve25519 = new MockGenericOpaqueCurve(curve25519, hashFunctions);
    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve25519, hashFunctions, "25519-with-SHA-512-Test");
    KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);
    OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);
    OpaqueServer server = new DefaultOpaqueServer(oprf, hkdf, hashFunctions);
    String password = "650132";
    byte[] oprfSeed = OpaqueUtils.random(128);
    KeyPairRecord serverKeyPair = oprf.deriveKeyPair(OpaqueUtils.random(64), "serverKeyPair");
    performTest("25519 curve Test", client, server, oprfSeed, password, serverKeyPair, oprf.getContext());
  }
  @Test
  void hsmOpaqueTest() throws Exception {
    log.info("HSM Opaque Test with P256");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OprfFunctions oprf = new DefaultOprfFunction(p256Curve, hashFunctions, "HSM-Supported OPRF");
    KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);
    OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);
    KeyPairRecord serverKeyPair = oprf.deriveKeyPair(OpaqueUtils.random(64), "serverKeyPair");
    KeyPair serverKeyPariObjects = oprf.getKeyPair(serverKeyPair);
    OpaqueServer server = new DefaultOpaqueServer(oprf, hkdf, hashFunctions);
    server.setStaticOprfKeyPair(serverKeyPariObjects);
    String password = "650132";
    byte[] oprfSeed = OpaqueUtils.random(128);
    performTest("HSM Opaque Test with P256", client, server, oprfSeed, password,
      new OprfPrivateKey(serverKeyPariObjects), serverKeyPair.publicKey(), oprf.getContext());
  }
  @Test
  void hsmOpaqueTest255519() throws Exception {
    log.info("HSM Opaque Test with 25519");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve opaqueCurve25519 = new MockGenericOpaqueCurve(ECNamedCurveTable.getParameterSpec("curve25519"), hashFunctions);
    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve25519, hashFunctions, "HSM-Supported OPRF");
    KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);
    OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);
    KeyPairRecord serverKeyPair = oprf.deriveKeyPair(OpaqueUtils.random(64), "serverKeyPair");
    KeyPair serverKeyPariObjects = oprf.getKeyPair(serverKeyPair);
    OpaqueServer server = new DefaultOpaqueServer(oprf, hkdf, hashFunctions);
    server.setStaticOprfKeyPair(serverKeyPariObjects);
    String password = "650132";
    byte[] oprfSeed = OpaqueUtils.random(128);
    performTest("HSM Opaque Test with 25519", client, server, oprfSeed, password,
      new OprfPrivateKey(serverKeyPariObjects), serverKeyPair.publicKey(), oprf.getContext());
  }

  void performTest(String message, OpaqueClient client, OpaqueServer server, byte[] oprfSeed, String password ,
    KeyPairRecord serverKeyPair, byte[] context)
    throws Exception {
    performTest(message, client, server, oprfSeed, password, null, null, null,
      new OprfPrivateKey(serverKeyPair.privateKey()), serverKeyPair.publicKey(), context);
  }
  void performTest(String message, OpaqueClient client, OpaqueServer server, byte[] oprfSeed, String password ,
    OprfPrivateKey serverPrivateKey, byte[] serverPublicKey, byte[] context)
    throws Exception {
    performTest(message, client, server, oprfSeed, password, null, null, null,
      serverPrivateKey, serverPublicKey, context);
  }

  void performTest(
    String message,
    OpaqueClient client,
    OpaqueServer server,
    byte[] oprfSeed,
    String passwordStr,
    String clientIdentityStr,
    String serverIdentityStr,
    String credentialIdentifierStr,
    OprfPrivateKey serverPrivateKey,
    byte[] serverPublicKey,
    byte[] context
  ) throws Exception {

    byte[] clientIdentity = Optional.ofNullable(clientIdentityStr).orElse("alice").getBytes();
    byte[] serverIdentity = Optional.ofNullable(serverIdentityStr).orElse("bob").getBytes();
    byte[] credentialIdentifier = Optional.ofNullable(credentialIdentifierStr).orElse("1234").getBytes();
    byte[] password = Optional.ofNullable(passwordStr).orElse("S3cr3t").getBytes(StandardCharsets.UTF_8);

    log.info("Initial Values:\n{}", SLB.getInstance()
      .append(TU.hex("Passord", clientIdentity)).appendLine(" (" + new String(clientIdentity) + ")")
      .append(TU.hex("Client Identity", clientIdentity)).appendLine(" (" + new String(clientIdentity) + ")")
      .append(TU.hex("Server Identity", serverIdentity)).appendLine(" (" + new String(serverIdentity) + ")")
      .append(TU.hex("Credential Identifier", credentialIdentifier)).appendLine(" (" + new String(credentialIdentifier) + ")")
      .append(TU.hex("Context", context)).appendLine(" (" + new String(context) + ")")
      .appendLine(TU.hex("OPRF Seed", oprfSeed))
      .appendLine(TU.hex("Server Public key", serverPublicKey))
      .append(serverPrivateKey.isByteValue() ? TU.hex("Server Private Key", serverPrivateKey.getPrivateKeyBytes()) + "\n" : "")
      );

    RegistrationRequestResult registrationRequest = client.createRegistrationRequest(password);
    log.info("Registration request:\n{}", SLB.getInstance()
      .appendLine(TU.hex("Blinded message", registrationRequest.registrationRequest().blindedMessage()))
      .appendLine(TU.hex("Blind", registrationRequest.blind())));

    byte[] regRequestToServer = registrationRequest.registrationRequest().getEncoded();

    RegistrationResponse registrationResponse = server.createRegistrationResponse(
      regRequestToServer, serverPublicKey, credentialIdentifier, oprfSeed);
    log.info("Registration response:\n{}", SLB.getInstance()
      .appendLine(TU.hex("Evaluated message", registrationResponse.evaluatedMessage()))
      .appendLine(TU.hex("Server public key", registrationResponse.serverPublicKey()))
    );

    byte[] regResponseToClient = registrationResponse.getEncoded();

    RegistrationFinalizationResult registrationFinalizationResult = client.finalizeRegistrationRequest(
      password, registrationRequest.blind(), regResponseToClient, serverIdentity,
      clientIdentity);
    log.info("Registration finalization result:\n{}", SLB.getInstance()
      .appendLine(TU.hex("Export key", registrationFinalizationResult.exportKey()))
      .appendLine(TU.hex("Client public key", registrationFinalizationResult.registrationRecord().clientPublicKey()))
      .appendLine(TU.hex("Masking key", registrationFinalizationResult.registrationRecord().maskingKey()))
      .appendLine(TU.hex("Envelope nonce", registrationFinalizationResult.registrationRecord().envelope().nonce()))
      .appendLine(TU.hex("Envelope authTag", registrationFinalizationResult.registrationRecord().envelope().authTag()))
    );

    byte[] registrationRecord = registrationFinalizationResult.registrationRecord().getEncoded();

    ClientState clientState = new ClientState();
    KE1 ke1 = client.generateKe1(password, clientState);
    log.info("Generated Ke1\n{}", SLB.getInstance()
      .appendLine(TU.hex("Auth Request - client public key", ke1.authRequest().clientPublicKey()))
      .appendLine(TU.hex("Auth Request - client nonce", ke1.authRequest().clientNonce()))
      .appendLine(TU.hex("Credential request - blinded message", ke1.credentialRequest().blindedMessage()))
      .appendLine(TU.hex("State - Client Secret", clientState.getClientAkeState().getClientSecret()))
      .appendLine(TU.hex("State - Blind", clientState.getBlind()))
    );

    byte[] ke1Bytes = ke1.getEncoded();

    ServerState serverState = new ServerState();
    KE2 ke2 = server.generateKe2(serverIdentity, serverPrivateKey, serverPublicKey,
      registrationRecord, credentialIdentifier, oprfSeed, ke1Bytes, clientIdentity,
      serverState);
    log.info("Server generated Ke2\n{}", SLB.getInstance()
      .appendLine(TU.hex("Auth response - Server public key share", ke2.authResponse().serverPublicKeyShare()))
      .appendLine(TU.hex("Auth response - Server mac", ke2.authResponse().serverMac()))
      .appendLine(TU.hex("Auth response - Server nonce", ke2.authResponse().serverNonce()))
      .appendLine(TU.hex("Credential Response - Masked response", ke2.credentialResponse().maskedResponse()))
      .appendLine(TU.hex("Credential Response - Masking nonce", ke2.credentialResponse().maskingNonce()))
      .appendLine(TU.hex("Credential Response - Evaluated message", ke2.credentialResponse().evaluatedMessage()))
      .appendLine(TU.hex("Server State - Expected client Mac", serverState.getAkeState().getExpectedClientMac()))
      .appendLine(TU.hex("Server State - Session Key", serverState.getAkeState().getSessionKey()))
    );

    byte[] ke2Bytes = ke2.getEncoded();

    ClientKeyExchangeResult clientKeyExchangeResult = client.generateKe3(clientIdentity, serverIdentity, ke2Bytes,
      clientState);
    log.info("Client generated Ke3\n{}", SLB.getInstance()
      .appendLine(TU.hex("Ke3 Client Mac", clientKeyExchangeResult.ke3().clientMac()))
      .appendLine(TU.hex("Client export key", clientKeyExchangeResult.exportKey()))
      .appendLine(TU.hex("Client derived session key", clientKeyExchangeResult.sessionKey()))
    );

    byte[] ke3Bytes = clientKeyExchangeResult.ke3().getEncoded();

    byte[] sessionKey = server.serverFinish(ke3Bytes, serverState);
    log.info("Server finish\n{}", SLB.getInstance()
      .appendLine(TU.hex("Server derived session key: {}", sessionKey))
    );

    log.info("Registration protocol exchange:\n{}", SLB.getInstance()
      .appendLine(TU.hex("Registration request", regRequestToServer))
      .appendLine(TU.hex("Registration response", regResponseToClient))
      .appendLine(TU.hex("Registration Record", registrationRecord))
    );

    log.info("Authentication exchange:\n{}", SLB.getInstance()
      .appendLine(TU.hex("KE1", ke1Bytes))
      .appendLine(TU.hex("KE2", ke2Bytes))
      .appendLine(TU.hex("KE3", ke3Bytes))
    );


    assertArrayEquals(clientKeyExchangeResult.sessionKey(), sessionKey);
    log.info("OPAQUE key generation successful!");
  }


  static byte[] getDst(String contextStrng) {
    return ("HashToGroup-" + contextStrng).getBytes(StandardCharsets.UTF_8);
  }

}
