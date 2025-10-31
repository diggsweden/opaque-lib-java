// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/**
 * Server state data.
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
