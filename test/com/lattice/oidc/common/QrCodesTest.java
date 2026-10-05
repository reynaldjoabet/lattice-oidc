package com.lattice.oidc.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import org.junit.Test;

public class QrCodesTest {

  @Test
  public void rendersModulesAsOneSvgPathWithAnAccessibleLabel() {
    String svg = QrCodes.svg("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fx", "Offer \"A\"");
    assertTrue(svg.startsWith("<svg"));
    assertTrue("version 1 is 21 modules; with the border the view box is larger", svg.contains("viewBox=\"0 0 "));
    assertTrue(svg.contains("h1v1h-1z"));
    assertTrue("the label is escaped", svg.contains("aria-label=\"Offer &quot;A&quot;\""));
  }

  @Test
  public void theCodeReadsBackAsTheText() throws Exception {
    String uri = "otpauth://totp/Lattice:jane%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Lattice&algorithm=SHA1&digits=6&period=30";
    assertEquals(uri, read(QrCodes.modules(uri)));
    assertEquals("non-ASCII text survives", "Zoë · 東京", read(QrCodes.modules("Zoë · 東京")));
  }

  /** Decodes the modules the way a phone camera would: as an image with a quiet zone. */
  private static String read(BitMatrix modules) throws Exception {
    int scale = 4;
    int border = 4;
    int size = (modules.getWidth() + border * 2) * scale;
    int[] pixels = new int[size * size];
    for (int y = 0; y < size; y++) {
      for (int x = 0; x < size; x++) {
        int moduleX = x / scale - border;
        int moduleY = y / scale - border;
        boolean dark =
            moduleX >= 0 && moduleY >= 0 && moduleX < modules.getWidth() && moduleY < modules.getHeight() && modules.get(moduleX, moduleY);
        pixels[y * size + x] = dark ? 0xFF000000 : 0xFFFFFFFF;
      }
    }
    BinaryBitmap image = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(size, size, pixels)));
    return new QRCodeReader().decode(image).getText();
  }
}
