// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.client;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

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
