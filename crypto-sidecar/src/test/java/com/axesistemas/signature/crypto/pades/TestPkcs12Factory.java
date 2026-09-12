package com.axesistemas.signature.crypto.pades;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

final class TestPkcs12Factory {

  static final String PASSWORD = "test-password";

  private TestPkcs12Factory() {}

  static Path create(Path directory) throws Exception {
    Files.createDirectories(directory);
    Path pfx = directory.resolve("test-signer.p12");
    String executable = Path.of(
        System.getProperty("java.home"),
        "bin",
        isWindows() ? "keytool.exe" : "keytool"
    ).toString();

    Process process = new ProcessBuilder(
        executable,
        "-genkeypair",
        "-alias", "signer",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-sigalg", "SHA256withRSA",
        "-dname", "CN=AXESISTEMAS TEST SIGNER,O=Axesistemas,C=BR",
        "-validity", "3650",
        "-storetype", "PKCS12",
        "-keystore", pfx.toString(),
        "-storepass", PASSWORD,
        "-keypass", PASSWORD,
        "-noprompt"
    ).redirectErrorStream(true).start();

    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int exit = process.waitFor();
    if (exit != 0) {
      throw new IOException("keytool failed: " + output);
    }
    return pfx;
  }

  private static boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase().contains("win");
  }
}
