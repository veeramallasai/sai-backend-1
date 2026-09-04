package com.farmtohome.api.auth;

import com.farmtohome.api.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/auth/email-otp", "/auth/email-otp", "/email-otp", "/api/email-otp"})
public class EmailOtpController {
  private final EmailOtpService service;

  public EmailOtpController(EmailOtpService service) {
    this.service = service;
  }

  @PostMapping("/send")
  ApiResponse<Map<String, Object>> send(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "mail");
    return ApiResponse.ok(service.send(uid, email), "Email OTP sent.");
  }

  @PostMapping("/resend")
  ApiResponse<Map<String, Object>> resend(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "mail");
    return ApiResponse.ok(service.resend(uid, email), "Email OTP resent.");
  }

  @PostMapping("/verify")
  ApiResponse<Map<String, Object>> verify(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "mail");
    String otp = extractParam(body, request, "otp", "code", "verificationCode", "verification_code", "rawOtp", "raw_otp", "otpCode", "otp_code", "passcode", "pin", "token");
    return ApiResponse.ok(
        service.verify(uid, email, otp),
        "Email verified successfully.");
  }

  @GetMapping("/status")
  ApiResponse<Map<String, Object>> status(Principal principal) {
    String uid = principal == null ? "dev_user" : principal.getName();
    return ApiResponse.ok(service.status(uid));
  }

  private String extractParam(Map<String, Object> body, HttpServletRequest request, String... keys) {
    String fromBody = extractString(body, keys);
    if (fromBody != null && !fromBody.isBlank()) {
      return fromBody;
    }
    if (request != null) {
      for (String key : keys) {
        String val = request.getParameter(key);
        if (val != null && !val.isBlank() && !"null".equalsIgnoreCase(val.trim())) {
          return val.trim();
        }
      }
    }
    return null;
  }

  private String extractString(Map<String, Object> map, String... keys) {
    if (map == null) return null;
    for (String key : keys) {
      for (Map.Entry<String, Object> entry : map.entrySet()) {
        if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key) && entry.getValue() != null) {
          String str = String.valueOf(entry.getValue()).trim();
          if (!str.isEmpty() && !str.equalsIgnoreCase("null")) {
            return str;
          }
        }
      }
    }
    for (Object val : map.values()) {
      if (val instanceof Map<?, ?> nested) {
        @SuppressWarnings("unchecked")
        String found = extractString((Map<String, Object>) nested, keys);
        if (found != null) return found;
      }
    }
    return null;
  }
}

