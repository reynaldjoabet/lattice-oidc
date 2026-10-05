package com.lattice.oidc.common;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** QR codes as inline SVG (no images to serve, no JavaScript; allowed by the CSP). */
public final class QrCodes {
  private QrCodes() {}

  /** Quiet zone around the code, in modules (the specification asks for 4; the page adds padding). */
  private static final int BORDER = 2;

  /** An SVG of {@code text} as a QR code with medium error correction, one path for all modules. */
  public static String svg(String text, String label) {
    BitMatrix qr = modules(text);
    int size = qr.getWidth() + BORDER * 2;
    StringBuilder path = new StringBuilder();
    for (int y = 0; y < qr.getHeight(); y++) {
      for (int x = 0; x < qr.getWidth(); x++) {
        if (qr.get(x, y)) {
          path.append('M').append(x + BORDER).append(',').append(y + BORDER).append("h1v1h-1z");
        }
      }
    }
    return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " + size + " " + size
        + "\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"" + escape(label) + "\">"
        + "<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>"
        + "<path fill=\"#1b1f2a\" d=\"" + path + "\"/></svg>";
  }

  /** The code's modules, one bit each (size 0 and margin 0: no scaling, no quiet zone). */
  static BitMatrix modules(String text) {
    try {
      return new QRCodeWriter()
          .encode(
              text,
              BarcodeFormat.QR_CODE,
              0,
              0,
              Map.of(
                  EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M,
                  EncodeHintType.CHARACTER_SET, StandardCharsets.UTF_8.name(),
                  EncodeHintType.MARGIN, 0));
    } catch (WriterException e) {
      // Only when the text is too long for the largest QR code (about 2,300 characters at level M).
      throw new IllegalArgumentException("Too long for a QR code: " + text.length() + " characters", e);
    }
  }

  private static String escape(String text) {
    return text.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
