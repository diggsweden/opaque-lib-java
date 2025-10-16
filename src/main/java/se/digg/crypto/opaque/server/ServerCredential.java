package se.digg.crypto.opaque.server;

import java.security.KeyPair;

/**
 * Server credential record
 */
public record ServerCredential(
  KeyPair keyPair
) {

  public int getPkSize(){
    return 0;
  }

}
