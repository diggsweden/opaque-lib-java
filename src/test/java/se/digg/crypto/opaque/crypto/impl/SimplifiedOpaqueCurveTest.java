// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto.impl;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.opaque.crypto.HashFunctions;
import se.digg.crypto.opaque.utils.TU;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Test class for SimplifiedOpaqueCurve. The class tests the `hashToGroup` method.
 */
@Slf4j
public class SimplifiedOpaqueCurveTest {

  private static SimplifiedOpaqueCurve curve;
  private static SimplifiedOpaqueCurve curveFast;
  private static SimplifiedOpaqueCurve curveWithLogging;


  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    HashFunctions hashFunctions = new HashFunctions(new SHA256Digest(), new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT)); // provide a proper HashFunctions instance
    ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("P-256"); // provide a proper ECParameterSpec instance

    curve = new SimplifiedOpaqueCurve(parameterSpec, hashFunctions);
    curveFast = new SimplifiedOpaqueCurve(parameterSpec, hashFunctions, 16);
    curveWithLogging = new SimplifiedOpaqueCurve(parameterSpec, hashFunctions);
    curveWithLogging.setDevMode(true);
  }

  @Test
  public void testHashToGroup() {

    // Define parameters

    for (int i = 0 ; i<50 ; i ++) {
      String password = "sdflkj098234sdf-" + i;
      try {
        long startTime = System.nanoTime();
        // Test hashToGroup
        performHashToGroupTest(password, curveWithLogging);
        long endTime = System.nanoTime();
        log.info("Time taken for hashToGroup: " + (endTime - startTime) + " ms");
      } catch (Exception e) {
        fail("Exception occurred during test: " + e.getMessage());
      }
    }

  }

  @Test
  void testTiming() throws Exception {
    

    // Checking distribution of bad and good points:
    performHashToGroupTest("sdflkj098234sdf-1", curveWithLogging);
    performHashToGroupTest("sdflkj098234sdf-38", curveWithLogging);

    // Checking timing differences
    performTimingTest("sdflkj098234sdf-1", 100, curve, true);
    performTimingTest("sdflkj098234sdf-38", 100, curve, true);
    performTimingTest("sdflkj098234sdf-1", 100, curve, false);
    performTimingTest("sdflkj098234sdf-38", 100, curve, false);
    performTimingTest("sdflkj098234sdf-1", 300, curve, false);
    performTimingTest("sdflkj098234sdf-38", 300, curve, false);

  }
  @Test
  void testTimingFastCurve() throws Exception {


    // Checking distribution of bad and good points:
    performHashToGroupTest("sdflkj098234sdf-1", curveWithLogging);
    performHashToGroupTest("sdflkj098234sdf-38", curveWithLogging);

    // Checking timing differences
    performTimingTest("sdflkj098234sdf-1", 100, curve, true);
    performTimingTest("sdflkj098234sdf-38", 100, curve, true);
    performTimingTest("sdflkj098234sdf-1", 100, curveFast, false);
    performTimingTest("sdflkj098234sdf-38", 100, curveFast, false);
    performTimingTest("sdflkj098234sdf-1", 1000, curveFast, false);
    performTimingTest("sdflkj098234sdf-38", 1000, curveFast, false);

  }

  @Test
  void testConsistency() throws Exception {

    ECPoint result = curve.hashToGroup("sdlkfjlksjdf-999".getBytes(StandardCharsets.UTF_8));
    log.info(TU.hex("Hash to point for 64 iterations: ", curve.serializeElement(result)));

    ECPoint result2 = curveFast.hashToGroup("sdlkfjlksjdf-999".getBytes(StandardCharsets.UTF_8));
    log.info(TU.hex("Hash to point for 16 iterations: ", curve.serializeElement(result2)));

    assertEquals(result, result2);
  }

  public long performTimingTest(String password, int iterations, SimplifiedOpaqueCurve curve, boolean scilent) {
    long startTime = System.nanoTime();
    List<Long> times = new ArrayList<>();
    long individualLow = 0;
    long individualHigh = 0;
    for (int i = 0; i < iterations; i++) {
      long individualStartTime = System.nanoTime();
      curve.hashToGroup(password.getBytes(StandardCharsets.UTF_8));
      long individualEndTime = System.nanoTime();
      long individualTime = individualEndTime - individualStartTime;
      times.add(individualTime);
      Collections.sort(times);
    }
    long endTime = System.nanoTime();
    individualLow = times.get(3);
    individualHigh = times.get(times.size() - 4);
    if (!scilent) {
      log.info("Time taken for hashToGroup for {}: {} ms - using {} itearations", password, (endTime - startTime)/1000000, iterations);
      log.info("Min time per operation: {} ns", individualLow);
      log.info("Max time per operation: {} ns", individualHigh);
      log.info("Mean time per operation: {} ns", (endTime - startTime)/iterations);
    }
    return endTime - startTime;
  }

  public void performHashToGroupTest(String password, SimplifiedOpaqueCurve curve) throws Exception {

    log.info("Testing password: {}", password);
    ECPoint result = curve.hashToGroup(password.getBytes(StandardCharsets.UTF_8));
    assertNotNull(result);

    log.info(TU.hex("Hash to point:", curve.serializeElement(result)));





  }




}
