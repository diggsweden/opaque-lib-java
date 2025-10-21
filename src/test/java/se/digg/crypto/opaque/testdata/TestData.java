// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.testdata;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Test data
 */
public class TestData {

  public static final ObjectMapper OBJECT_MAPPER;

  static {
    OBJECT_MAPPER = new ObjectMapper();
    OBJECT_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static ObjectWriter jsonPrettyPrinter() {
    return OBJECT_MAPPER.writerWithDefaultPrettyPrinter();
  }

  public static List<OPRFTestVectorData> getOprfTestVectors() {
    try {
      return OBJECT_MAPPER.readValue(TestData.class.getResourceAsStream("/oprf-vectors.json"),
        new TypeReference<>() {
        });
    }
    catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static List<OpaqueTestVectorData> getOpaqueTestVectors() {
    try {
      return OBJECT_MAPPER.readValue(TestData.class.getResourceAsStream("/opaque-test-vectors.json"),
        new TypeReference<>() {
        });
    }
    catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
