// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.testdata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Test vector data in Json
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OpaqueTestVectorData {

  Config config;
  Inputs inputs;
  Intermediates intermediates;
  Outputs outputs;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Config {

    @JsonProperty("Group")
    private String group;
    @JsonProperty("Hash")
    private String hash;
    @JsonProperty("KDF")
    private String kdf;
    @JsonProperty("KSF")
    private String ksf;
    @JsonProperty("MAC")
    private String mac;
    @JsonProperty("Name")
    private String name;
    @JsonProperty("Nh")
    private String nh;
    @JsonProperty("Nm")
    private String nm;
    @JsonProperty("Nok")
    private String nok;
    @JsonProperty("Npk")
    private String npk;
    @JsonProperty("Nsk")
    private String nsk;
    @JsonProperty("Nx")
    private String nx;
    @JsonProperty("OPRF")
    private String oprf;
  }
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Inputs {
    @JsonProperty("blind_login")
    private String blindLogin;
    @JsonProperty("blind_registration")
    private String blindRegistration;
    @JsonProperty("client_identity")
    private String clientIdentity;
    @JsonProperty("client_keyshare_seed")
    private String clientKeyshareSeed;
    @JsonProperty("client_nonce")
    private String clientNonce;
    @JsonProperty("credential_identifier")
    private String credentialIdentifier;
    @JsonProperty("envelope_nonce")
    private String envelopeNonce;
    @JsonProperty("masking_nonce")
    private String maskingNonce;
    @JsonProperty("oprf_seed")
    private String oprfSeed;
    @JsonProperty("password")
    private String password;
    @JsonProperty("server_identity")
    private String serverIdentity;
    @JsonProperty("server_keyshare_seed")
    private String serverKeyshareSeed;
    @JsonProperty("server_nonce")
    private String serverNonce;
    @JsonProperty("server_private_key")
    private String serverPrivateKey;
    @JsonProperty("server_public_key")
    private String serverPublicKey;
  }
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Intermediates {
    @JsonProperty("auth_key")
    private String authKey;
    @JsonProperty("client_mac_key")
    private String clientMacKey;
    @JsonProperty("client_public_key")
    private String clientPublicKey;
    @JsonProperty("envelope")
    private String envelope;
    @JsonProperty("handshake_secret")
    private String handshakeSecret;
    @JsonProperty("masking_key")
    private String maskingKey;
    @JsonProperty("oprf_key")
    private String oprfKey;
    @JsonProperty("randomized_password")
    private String randomizedPassword;
    @JsonProperty("server_mac_key")
    private String serverMacKey;
  }
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Outputs {
    @JsonProperty("KE1")
    private String ke1;
    @JsonProperty("KE2")
    private String ke2;
    @JsonProperty("KE3")
    private String ke3;
    @JsonProperty("export_key")
    private String exportKey;
    @JsonProperty("registration_request")
    private String registrationRequest;
    @JsonProperty("registration_response")
    private String registrationResponse;
    @JsonProperty("registration_upload")
    private String registrationUpload;
    @JsonProperty("session_key")
    private String sessionKey;
  }

}
