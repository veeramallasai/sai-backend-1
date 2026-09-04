package com.farmtohome.api.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {
  private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);
  private final String secretKey;

  public JwtUtil(@Value("${app.jwt.secret:farmtohome_secret_key_super_secure_jwt_token_key_2026_min_256_bits}") String secretKey) {
    this.secretKey = secretKey == null || secretKey.isBlank()
        ? "farmtohome_secret_key_super_secure_jwt_token_key_2026_min_256_bits"
        : secretKey;
  }

  public String generateToken(String uid, String email, String role) {
    long now = System.currentTimeMillis() / 1000L;
    long exp = now + (30L * 24L * 60L * 60L); // 30 days

    String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    String payload = String.format(
        "{\"sub\":\"%s\",\"email\":\"%s\",\"role\":\"%s\",\"iat\":%d,\"exp\":%d}",
        escape(uid), escape(email), escape(role == null ? "customer" : role), now, exp);

    String encodedHeader = urlEncode(header.getBytes(StandardCharsets.UTF_8));
    String encodedPayload = urlEncode(payload.getBytes(StandardCharsets.UTF_8));

    String data = encodedHeader + "." + encodedPayload;
    String signature = hmacSha256(data, secretKey);

    return data + "." + signature;
  }

  public String extractUid(String token) {
    if (token == null || token.isBlank()) return null;
    String cleanToken = token.startsWith("Bearer ") ? token.substring(7).trim() : token.trim();
    String[] parts = cleanToken.split("\\.");
    if (parts.length < 2) return cleanToken;

    try {
      byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
      String json = new String(decoded, StandardCharsets.UTF_8);
      int subIdx = json.indexOf("\"sub\":");
      if (subIdx != -1) {
        int start = json.indexOf("\"", subIdx + 6) + 1;
        int end = json.indexOf("\"", start);
        if (start > 0 && end > start) {
          return json.substring(start, end);
        }
      }
    } catch (Exception ex) {
      log.debug("Failed to extract UID from JWT payload: {}", ex.getMessage());
    }
    return cleanToken;
  }

  private String hmacSha256(String data, String secret) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
      mac.init(keySpec);
      byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
      return urlEncode(hash);
    } catch (Exception ex) {
      log.error("Error signing JWT token", ex);
      return "signature_error";
    }
  }

  private String urlEncode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private String escape(String input) {
    return input == null ? "" : input.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
