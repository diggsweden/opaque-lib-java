package se.digg.crypto.opaque.client;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.crypto.opaque.dto.KE1;

/**
 * Client AKE state
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ClientAkeState {
  private byte[] clientSecret;
  private KE1 ke1;
  private byte[] expectedClientMac;
  private byte[] sessionKey;
}
