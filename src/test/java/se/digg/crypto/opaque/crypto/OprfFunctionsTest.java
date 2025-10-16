package se.digg.crypto.opaque.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.impl.ArgonStretch;
import se.digg.crypto.opaque.crypto.impl.DefaultOprfFunction;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.server.keys.KeyPairRecord;
import se.digg.crypto.opaque.testimpl.MockGenericOpaqueCurve;
import se.digg.crypto.opaque.utils.TU;

/**
 * Testing OPRF
 */
@Slf4j
class OprfFunctionsTest {

  private final static SecureRandom RNG = new SecureRandom();

  private final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256");


  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }


  @Test
  void testHsmOprf() throws Exception {

    HashFunctions hashFunctions = new HashFunctions(new SHA256Digest(),
      new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve opaqueCurve = new MockGenericOpaqueCurve(ECNamedCurveTable.getParameterSpec("P-256"), hashFunctions);
    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve, hashFunctions, "test");
    KeyPair serverK = oprf.getKeyPair(oprf.deriveDiffieHellmanKeyPair(OpaqueUtils.random(20)));
    KeyPairRecord serverOprfKey = oprf.deriveDiffieHellmanKeyPair(OpaqueUtils.random(20));

    BigInteger blind = new BigInteger(256, RNG).mod(parameterSpec.getCurve().getOrder().subtract(BigInteger.ONE))
      .add(BigInteger.ONE);
    BigInteger blindInverse = blind.modInverse(parameterSpec.getCurve().getOrder());
    BigInteger inputScalar = new BigInteger(1, hashFunctions.hash("secret".getBytes())).mod(
      parameterSpec.getCurve().getOrder());


    log.info("Testing without blind");
    // Do calculation without blind
    ECPoint inputElementPoint = parameterSpec.getG().multiply(inputScalar);
    ECPoint evenFirstPass = oprf.blindEvaluate(new OprfPrivateKey(serverK), inputElementPoint);
    ECPoint evenExpectedResult = multiplyWithBytePrivateKey(serverOprfKey.privateKey(), evenFirstPass);
    log.info(TU.hex("Even padding result without blinding", evenExpectedResult.getEncoded(true)));

    //Blind and unblind
    ECPoint blinded = inputElementPoint.multiply(blind);
    ECPoint evenBlindedK = oprf.blindEvaluate(new OprfPrivateKey(serverK), blinded);
    log.info(TU.hex("Blinded with even Y", evenBlindedK.getEncoded(true)));
    ECPoint evenBlindEvaluate = multiplyWithBytePrivateKey(serverOprfKey.privateKey(), evenBlindedK);
    log.info(TU.hex("Even Blind evaluate", evenBlindEvaluate.getEncoded(true)));
    ECPoint evenUnblinded = evenBlindEvaluate.multiply(blindInverse);
    log.info(TU.hex("Even unblinded", evenUnblinded.getEncoded(true)));
    assertArrayEquals(opaqueCurve.getSharedSecret(evenExpectedResult), opaqueCurve.getSharedSecret(evenUnblinded));


    ECPoint firstPass = oprf.blindEvaluate(new OprfPrivateKey(serverK), inputElementPoint);
    ECPoint expectedResult = multiplyWithBytePrivateKey(serverOprfKey.privateKey(), firstPass);
    log.info(TU.hex("result without blinding", expectedResult.getEncoded(true)));
    ECPoint oddBlindedK = oprf.blindEvaluate(new OprfPrivateKey(serverK), blinded);
    log.info(TU.hex("Blinded", oddBlindedK.getEncoded(true)));
    ECPoint blindEvaluate = multiplyWithBytePrivateKey(serverOprfKey.privateKey(), oddBlindedK);
    log.info(TU.hex("Blind evaluate", blindEvaluate.getEncoded(true)));
    ECPoint unblinded = blindEvaluate.multiply(blindInverse);
    log.info(TU.hex("Odd unblinded", unblinded.getEncoded(true)));
    assertArrayEquals(opaqueCurve.serializeElement(expectedResult), opaqueCurve.serializeElement(unblinded));

  }

  @Test
  void test25519Blind() throws Exception {
    ECNamedCurveParameterSpec curve25519 = ECNamedCurveTable.getParameterSpec("curve25519");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve opaqueCurve25519 = new MockGenericOpaqueCurve(curve25519, hashFunctions);
    log.info("25519 curve blind test");
    log.info("Curve point serialization size: {}", opaqueCurve25519.getElementSerializationSize());
    log.info("Curve scalar serialization size {}", opaqueCurve25519.getScalarSize());
    log.info(TU.hex("Curve G point", opaqueCurve25519.serializeElement(opaqueCurve25519.getParameterSpec().getG())));
    blindTest(opaqueCurve25519, hashFunctions);

  }

  @Test
  void testP521Blind() throws Exception {
    ECNamedCurveParameterSpec curveP521Spec = ECNamedCurveTable.getParameterSpec("P-521");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve curveP521 = new MockGenericOpaqueCurve(curveP521Spec, hashFunctions);
    log.info("P-521 curve blind test");
    log.info("Curve point serialization size: {}", curveP521.getElementSerializationSize());
    log.info("Curve scalar serialization size {}", curveP521.getScalarSize());
    log.info(TU.hex("Curve G point", curveP521.serializeElement(curveP521.getParameterSpec().getG())));
    blindTest(curveP521, hashFunctions);

  }
  @Test
  void testP256Blind() throws Exception {
    ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("P-256");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve curve = new MockGenericOpaqueCurve(curveSpec, hashFunctions);
    log.info("P-256 curve blind test");
    log.info("Curve point serialization size: {}", curve.getElementSerializationSize());
    log.info("Curve scalar serialization size {}", curve.getScalarSize());
    log.info(TU.hex("Curve G point", curve.serializeElement(curve.getParameterSpec().getG())));
    blindTest(curve, hashFunctions);

  }

  @Test
  void fixMissingYTest() throws Exception {
    ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("P-256");
    HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT));
    OpaqueCurve curve = new MockGenericOpaqueCurve(curveSpec, hashFunctions);
    OprfFunctions oprf = new DefaultOprfFunction(curve, hashFunctions, "test");
    KeyPairRecord keyPairRecord = oprf.deriveDiffieHellmanKeyPair(OpaqueUtils.random(20));
    KeyPair serverK = oprf.getKeyPair(keyPairRecord);

    ECPoint pwPoint = curve.hashToGroup("Password".getBytes(StandardCharsets.UTF_8));
    // Evaluate PW Point with DiffieHellman
    byte[] xCoordinate = ((DefaultOprfFunction)oprf).deriveDiffieHellmanSharedSecret(serverK.getPrivate(), pwPoint);
    byte[] dhWithY = oprf.diffieHellman(new OprfPrivateKey(keyPairRecord.privateKey()), pwPoint.getEncoded(true));
    //byte[] xCoordinate = oprf.getCurve().getSharedSecret(oprf.deserializeElement(dhWithY));
    ECPoint evenYResult = oprf.deserializeElement(OpaqueUtils.concat(new byte[] { 0x02 }, xCoordinate));
    ECPoint oddYResult = oprf.deserializeElement(OpaqueUtils.concat(new byte[] { 0x03 }, xCoordinate));

    ECPoint controlPoint = pwPoint.add(curve.getParameterSpec().getG());
    // This control point should match the X coordinate of Z + Ks
    byte[] xControl = ((DefaultOprfFunction)oprf).deriveDiffieHellmanSharedSecret(serverK.getPrivate(), controlPoint);

    // Add with public
    ECPoint publicKeyPoint = oprf.deserializeElement(oprf.serializePublicKey(serverK.getPublic()));
    ECPoint pkPlusEvenY = evenYResult.add(publicKeyPoint);
    ECPoint pkPlusOddY = oddYResult.add(publicKeyPoint);

    log.info(TU.hex("DH Output Z", xCoordinate));
    log.info(TU.hex("DH Complete Point", dhWithY));
    log.info(TU.hex("(PW + G) * k Output Z", xControl));
    log.info(TU.hex("Ks + Z with EvenY", curve.getSharedSecret(pkPlusEvenY)));
    log.info(TU.hex("Ks + Z with OddY", curve.getSharedSecret(pkPlusOddY)));

    // Evaluate which is the correct guess
    byte[] xOfPkPlusEvenY = curve.getSharedSecret(pkPlusEvenY);
    byte[] xOfPkPlusOddY = curve.getSharedSecret(pkPlusOddY);
    boolean odd = Arrays.areEqual(xControl, xOfPkPlusOddY);
    boolean even = Arrays.areEqual(xControl, xOfPkPlusEvenY);
    if (!(odd || even)) {
      throw new RuntimeException("Illegal EC operation");
    }
    byte[] missingY = odd ? new byte[] { 0x03 } : new byte[] { 0x02 };
    log.info("Missing Y coordinate is: {}", Hex.toHexString(missingY));

    ECPoint recoveredDHPoint = curve.deserializeElement(Arrays.concatenate(missingY, xCoordinate));
    log.info(TU.hex("Recovered DH point", recoveredDHPoint.getEncoded(true)));

    assertArrayEquals(dhWithY, recoveredDHPoint.getEncoded(true));

    byte[] y = getY(xCoordinate, xControl, publicKeyPoint, oprf);
    assertArrayEquals(missingY, y);

    byte[] completeDhOpWithY = oprf.diffieHellman(new OprfPrivateKey(serverK), pwPoint.getEncoded(true));

    assertArrayEquals(recoveredDHPoint.getEncoded(true), completeDhOpWithY);


  }

  void blindTest(OpaqueCurve opaqueCurve, HashFunctions hashFunctions) throws Exception {

    OprfFunctions oprf = new DefaultOprfFunction(opaqueCurve, hashFunctions, "test");
    KeyPair serverK = oprf.getKeyPair(oprf.deriveDiffieHellmanKeyPair(OpaqueUtils.random(20)));
    KeyPairRecord oprfKey = oprf.deriveDiffieHellmanKeyPair("oprfKey".getBytes(StandardCharsets.UTF_8));

    BigInteger blind = opaqueCurve.randomScalar();
    BigInteger blindInverse = blind.modInverse(opaqueCurve.getParameterSpec().getCurve().getOrder());

    log.info("Testing without blind");
    // Do calculation without blinding
    ECPoint inputElement = opaqueCurve.hashToGroup("secret".getBytes());
    log.info(TU.hex("Password inputElement point", inputElement.getEncoded(true)));
    ECPoint unblindedOprfEvaluate = oprf.blindEvaluate(new OprfPrivateKey(serverK), inputElement);
    log.info(TU.hex("InputElement * oprfKey", unblindedOprfEvaluate.getEncoded(true)));
    ECPoint unblindedHsmEvaluate = multiplyWithPrivateKey(serverK, unblindedOprfEvaluate, oprf);
    log.info(TU.hex("Client secret = DiffieHellman(sk, (InputElement * oprfKey)", opaqueCurve.getSharedSecret(unblindedHsmEvaluate)));
    log.info(TU.hex("The real EC point used to derive the DH shared secret", unblindedHsmEvaluate.getEncoded(true)));

    //Blind and unblind softKey
    ECPoint blinded = inputElement.multiply(blind);
    log.info(TU.hex("Blinded input element", blinded.getEncoded(true)));
    ECPoint oprfEvaluate = oprf.blindEvaluate(new OprfPrivateKey(serverK), blinded);
    log.info(TU.hex("OPRF evaluate = blinded element * oprfKey", oprfEvaluate.getEncoded(true)));
    ECPoint hsmEvaluate = multiplyWithPrivateKey(serverK, oprfEvaluate, oprf);
    log.info(TU.hex("HSM Server evaluate = DiffieHellman(ks, (blinded element * oprfKey)", opaqueCurve.getSharedSecret(hsmEvaluate)));
    log.info(TU.hex("ECPoint(HSM Server evaluate) =  0x02 | HSM Server evaluate", hsmEvaluate.getEncoded(true)));
    ECPoint evenUnblinded = hsmEvaluate.multiply(blindInverse);
    log.info(TU.hex("Client unblind = ECPoint(HSM Server evaluate) * 1/b", evenUnblinded.getEncoded(true)));
    log.info(TU.hex("Derived shared secret", opaqueCurve.getSharedSecret(evenUnblinded)));
    assertArrayEquals(opaqueCurve.getSharedSecret(unblindedHsmEvaluate), opaqueCurve.getSharedSecret(evenUnblinded));
  }

  byte[] getY(byte[] sharedSecret, byte[] controlX, ECPoint publicKey, OprfFunctions oprf)
    throws DeserializationException {

    byte[] evenY = new byte[]{0x02};
    byte[] oddY = new byte[]{0x03};

    ECPoint evenSecret = oprf.deserializeElement(Arrays.concatenate(evenY, sharedSecret));
    ECPoint oddSecret = oprf.deserializeElement(Arrays.concatenate(oddY, sharedSecret));
    byte[] evenSecretPlusPK = oprf.getCurve().getSharedSecret(evenSecret.add(publicKey));
    byte[] oddSecretPlusPK = oprf.getCurve().getSharedSecret(oddSecret.add(publicKey));

    if (Arrays.areEqual(evenSecretPlusPK, controlX)){
      return evenY;
    }
    if (Arrays.areEqual(oddSecretPlusPK, controlX)){
      return oddY;
    }
    throw new DeserializationException("Illegal DH point data");
  }

  ECPoint multiplyWithBytePrivateKey(byte[] privateKey, ECPoint point) {
    return point.multiply(new BigInteger(1, privateKey));
  }

  ECPoint multiplyWithPrivateKey(KeyPair keyPair, ECPoint point, OprfFunctions oprf)
    throws Exception {

    byte[] sharedSecretPoint = oprf.diffieHellman(new OprfPrivateKey(keyPair), point.getEncoded(true));
    return oprf.deserializeElement(sharedSecretPoint);
  }

}