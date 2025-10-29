// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.crypto;

/**
 * Interface for individual implementations of stretch algorithms
 *
 * <p>
 *    Applying a key stretching function to the output of the OPRF greatly
 *    increases the cost of an offline attack upon the compromise of the
 *    credential file at the server.  Applications SHOULD select parameters
 *    for the KSF that balance cost and complexity across different client
 *    implementations and deployments.  Note that in OPAQUE, the key
 *    stretching function is executed by the client, as opposed to the
 *    server in traditional password hashing scenarios.  This means that
 *    applications must consider a tradeoff between the performance of the
 *    protocol on clients (specifically low-end devices) and protection
 *    against offline attacks after a server compromise
 * </p>
 */
public interface StretchAlgorithm {

  /**
   * Stretch a message
   *
   * @param message message
   * @param length length of the stretched message
   * @return stretched message
   */
  byte[] stretch(byte[] message, int length);

}
