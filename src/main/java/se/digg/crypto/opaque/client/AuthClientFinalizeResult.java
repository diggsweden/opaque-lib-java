package se.digg.crypto.opaque.client;

import se.digg.crypto.opaque.dto.KE3;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public record AuthClientFinalizeResult(
  KE3 ke3,
  byte[] sessionKey
) {
}
