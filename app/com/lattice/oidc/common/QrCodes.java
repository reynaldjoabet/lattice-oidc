package com.lattice.oidc.common;

import io.nayuki.qrcodegen.QrCode;

/** QR codes as inline SVG (no images to serve, no JavaScript; allowed by the CSP). */
public final class QrCodes {
  private QrCodes() {}

  /** Quiet zone around the code, in modules (the specification asks for 4; the page adds padding). */
  private static final int BORDER = 2;

  /** An SVG of {@code text} as a QR code with medium error correction, one path for all modules. */
  public static String svg(String text, String label) {
    QrCode qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
    int size = qr.size + BORDER * 2;
    StringBuilder path = new StringBuilder();
    for (int y = 0; y < qr.size; y++) {
      for (int x = 0; x < qr.size; x++) {
        if (qr.getModule(x, y)) {
          path.append('M').append(x + BORDER).append(',').append(y + BORDER).append("h1v1h-1z");
        }
      }
    }
    return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + size + " " + size
        + "\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"" + escape(label) + "\">"
        + "<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>"
        + "<path fill=\"#1b1f2a\" d=\"" + path + "\"/></svg>";
  }

  private static String escape(String text) {
    return text.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
