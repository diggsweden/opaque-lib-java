// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.error.InvalidInputException;

/**
 * Functions to derive a DST based on a correct context string for use in OPRF and OPAQUE.
 */

public class DstContext {

  public static final String VERSION_OPRFV1 = "OPRFV1";
  public static final String IDENTIFIER_P256_SHA256 = "P256-SHA256";
  public static final String IDENTIFIER_DECAF448_SHAKE256 = "decaf448-SHAKE256";
  public static final String IDENTIFIER_P384_SHA384 = "P384-SHA384";
  public static final String IDENTIFIER_P521_SHA512 = "P521-SHA512";
  public static final int MODE_OPRF = 0;
  public static final int MODE_VOPRF = 1;
  public static final int MODE_POPRF = 2;

  private final String version;
  private final int mode;
  private final String identifier;

  /**
   * Creates a DST (Domain Separation Tag) context object.
   *
   * @param version the version of the OPRF DST context.
   * @param mode the mode of the DST context.
   * @param identifier the identifier of the EC curve params
   */
  public DstContext(String version, int mode, String identifier) {
    this.version = version;
    this.mode = mode;
    this.identifier = identifier;
  }

  /**
   * Creates a DST (Domain Separation Tag) context object with a default version set to OPRFV1.
   *
   * @param mode the mode of the DST context.
   * @param identifier the identifier of the EC curve params
   */
  public DstContext(int mode, String identifier) {
    this.version = VERSION_OPRFV1;
    this.mode = mode;
    this.identifier = identifier;
  }

  /**
   * Creates a DST (Domain Separation Tag) context object with a default version set to OPRFV1 and
   * mode set to 0 (OPRF).
   *
   * @param identifier the identifier of the EC curve params
   */
  public DstContext(String identifier) {
    this.version = VERSION_OPRFV1;
    this.mode = MODE_OPRF;
    this.identifier = identifier;
  }

  public byte[] getHash2CurveDST() {
    return OpaqueUtils.concat("HashToGroup-", getContextString());
  }

  public byte[] getHash2ScalarDefaultDST() {
    return OpaqueUtils.concat("HashToScalar-", getContextString());
  }

  public byte[] getDomainSeparationTag(String domain) {
    return OpaqueUtils.concat(domain, getContextString());
  }

  public byte[] getContextString() {
    try {
      return OpaqueUtils.concat(version, "-", OpaqueUtils.i2osp(mode, 1), "-", identifier);
    } catch (InvalidInputException e) {
      throw new RuntimeException(e);
    }
  }


}
