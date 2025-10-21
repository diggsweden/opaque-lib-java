// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.utils;

/**
 * Test Utils
 */
public class TU {

  public static String hex(String label, byte[] byteArray) {
    return new StringBuilder()
      .append(label)
      .append(" (Size: ")
      .append(byteArray.length)
      .append(")\n")
      .append(hex(byteArray))
      .toString();
  }

  public static String hex(byte[] byteArray) {
    return hex(byteArray, 4, 10, 4);
  }

  public static String hex(byte[] byteArray, int indentation, int group, int groupsPerLine) {
    StringBuilder sb = new StringBuilder();
    String ind = "                      ".substring(0, indentation);

    for (int i = 0; i < byteArray.length; i++) {
      // Convert byte to hex string
      String hex = String.format("%02X", byteArray[i]);
      // Group ending
      if (i % group == 0) {
        if (i % (group * groupsPerLine) == 0) {
          if (i != 0) {
            sb.append("\n");
          }
          sb.append(ind);
        } else {
          sb.append(" ");
        }
      }
      // Add hex string with a space
      sb.append(hex).append(" ");
    }
    return sb.toString();
  }

}
