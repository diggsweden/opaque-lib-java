// SPDX-FileCopyrightText: 2025 The Opaque Java Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.opaque.utils;

/**
 * String line builder
 */
public class SLB {

  public static SLB getInstance(){
    return new SLB();
  }

  private StringBuilder sb = new StringBuilder();

  public SLB append(Object o){
    sb.append(o);
    return this;
  }
  public SLB appendLine(Object o){
    sb.append(o).append("\n");
    return this;
  }
  public SLB appendLines(Object o){
    sb.append(o).append("\n\n");
    return this;
  }

  @Override
  public String toString() {
    return sb.toString();
  }

}
