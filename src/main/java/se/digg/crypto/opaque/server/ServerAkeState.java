package se.digg.crypto.opaque.server;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Server AKE State
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ServerAkeState {

  private byte[] expectedClientMac;
  private byte[] sessionKey;
}
