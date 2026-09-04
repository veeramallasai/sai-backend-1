package com.farmtohome.api;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class FarmToHomeApiApplication {
  public static void main(String[] args) {
    loadEnv();
    SpringApplication.run(FarmToHomeApiApplication.class, args);
  }

  private static void loadEnv() {
    File envFile = new File(".env");
    if (envFile.exists() && envFile.isFile()) {
      try {
        List<String> lines = Files.readAllLines(envFile.toPath());
        for (String line : lines) {
          String trimmed = line.trim();
          if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
          int eq = trimmed.indexOf('=');
          if (eq > 0) {
            String key = trimmed.substring(0, eq).trim();
            String val = trimmed.substring(eq + 1).trim();
            if (System.getProperty(key) == null && System.getenv(key) == null) {
              System.setProperty(key, val);
            }
          }
        }
      } catch (Exception ignored) {}
    }
  }
}
