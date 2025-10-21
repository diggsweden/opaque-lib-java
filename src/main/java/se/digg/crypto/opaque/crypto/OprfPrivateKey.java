// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

import java.security.KeyPair;

import lombok.Getter;

/**
 * Stores Oprf PrivateKey data
 */
public class OprfPrivateKey {

  @Getter private KeyPair keyPair;
  @Getter private byte[] privateKeyBytes;
  @Getter boolean byteValue;

  public OprfPrivateKey(KeyPair keyPair) {
    this.keyPair = keyPair;
    this.byteValue = false;
  }

  public OprfPrivateKey(byte[] privateKeyBytes) {
    this.privateKeyBytes = privateKeyBytes;
    this.byteValue = true;
  }
}
