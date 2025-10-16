package se.digg.crypto.opaque.crypto.impl;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.crypto.StretchAlgorithm;

/**
 * Implementation of the Argon stretch algorithm
 */
@Slf4j
public class ArgonStretch implements StretchAlgorithm {

  public static final String ARGON_PROFILE_DEFAULT = "default";
  public static final String ARGON_PROFILE_IDENTITY = "identity";
  /** Predefined Argon profiles */
  public static final Map<String, Argon2Parameters> predefinedProfile;

  static{
    predefinedProfile = new HashMap<>();
    predefinedProfile.put(ARGON_PROFILE_DEFAULT, new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withSalt(OpaqueUtils.zeroes(16))
      .withParallelism(4)
      .withMemoryAsKB(2^21)
      .withIterations(1)
      .withVersion(0x13)
      .build());
    predefinedProfile.put(ARGON_PROFILE_IDENTITY, null);
  }

  /** Argon configuration parameters */
  private Argon2Parameters parameters;

  /**
   * Constructor specifying configuration parameters
   *
   * @param parameters argon configuration parameters
   */
  public ArgonStretch(Argon2Parameters parameters) {
    this.parameters = parameters;
  }

  /**
   * Constructor selecting configuration based on defined profile
   *
   * @param argonProfile
   */
  public ArgonStretch(String argonProfile) {
    if (!predefinedProfile.containsKey(argonProfile)){
      throw new IllegalArgumentException("Unsupported ARGON Profile");
    }
    parameters = predefinedProfile.get(argonProfile);
  }

  /** {@inheritDoc} */
  @Override public byte[] stretch(byte[] message, int length) {
    if (parameters == null) {
      log.debug("Running in identity mode. Returning input");
      return message;
    }
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(parameters);
    byte[] stretched = new byte[length];
    generator.generateBytes(message, stretched);
    return stretched;
  }
}
