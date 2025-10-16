package se.digg.crypto.opaque.server;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Server state data
 */
@Data
@AllArgsConstructor
@Builder
public class ServerState {
  private ServerAkeState akeState;

  public ServerState() {
    this.akeState = new ServerAkeState();
  }
}
