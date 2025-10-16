package se.digg.crypto.opaque.client;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Client state
 */
@Data
@AllArgsConstructor
@Builder
public class ClientState {
  private byte[] password;
  private byte[] blind;
  private ClientAkeState clientAkeState;

  public ClientState() {
    this.clientAkeState = new ClientAkeState();
  }
}
