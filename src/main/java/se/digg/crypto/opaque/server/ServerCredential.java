// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.server;

import java.security.KeyPair;

/**
 * Server credential record
 */
public record ServerCredential(
    KeyPair keyPair) {

  public int getPkSize() {
    return 0;
  }

}
