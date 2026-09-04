package com.farmtohome.api.auth;

import com.farmtohome.api.common.ApiException;
import com.farmtohome.api.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/auth/password-setup", "/auth/password-setup", "/password-setup", "/api/password-setup"})
public class PasswordSetupController {
  private static final Logger log = LoggerFactory.getLogger(PasswordSetupController.class);
  private final PasswordSetupService service;

  public PasswordSetupController(PasswordSetupService service) {
    this.service = service;
  }

  @PostMapping("/send")
  public ApiResponse<Map<String, Object>> send(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to", "mail");
    log.info("Password setup OTP requested for email: {}, uid: {}", email, uid);
    return ApiResponse.ok(service.send(uid, email), "Password setup OTP sent.");
  }

  @PostMapping("/resend")
  public ApiResponse<Map<String, Object>> resend(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to", "mail");
    log.info("Password setup OTP resend requested for email: {}, uid: {}", email, uid);
    return ApiResponse.ok(service.send(uid, email), "Password setup OTP resent.");
  }

  @PostMapping("/verify")
  public ApiResponse<Map<String, Object>> verify(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to", "mail");
    String otp = extractParam(body, request, "otp", "code", "verificationCode", "verification_code", "rawOtp", "raw_otp", "otpCode", "otp_code", "passcode", "pin", "token", "user_otp", "email_otp", "confirm_otp");
    log.info("Password setup OTP verify requested. bodyKeys={}, email={}, otp={}", body == null ? "null" : body.keySet(), email, otp);
    return ApiResponse.ok(
        service.verify(uid, email, otp),
        "OTP verified successfully.");
  }

  @PostMapping({"/confirm", "/reset", "/complete"})
  public ApiResponse<Map<String, Object>> confirm(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to", "mail");
    String otp = extractParam(body, request, "otp", "code", "verificationCode", "verification_code", "rawOtp", "raw_otp", "otpCode", "otp_code", "passcode", "pin", "token", "user_otp", "email_otp", "confirm_otp");
    String password = extractParam(body, request, "password", "newPassword", "new_password", "confirmPassword", "confirm_password", "pass", "user_password");
    log.info("Password setup OTP confirm requested. bodyKeys={}, email={}, otp={}", body == null ? "null" : body.keySet(), email, otp);

    if (password == null || password.isBlank()) {
      throw new ApiException(HttpStatus.BAD_REQUEST, "New password is required.");
    }

    return ApiResponse.ok(
        service.confirm(uid, email, otp, password),
        "Password updated successfully.");
  }

  @PostMapping({"/login", "/password-login"})
  public ApiResponse<Map<String, Object>> login(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String identifier = extractParam(body, request, "email", "identifier", "username", "targetEmail", "user_email", "phone", "phoneNumber", "mobile", "recipient", "to", "mail");
    String password = extractParam(body, request, "password", "rawPassword", "passcode", "secret", "pin", "newPassword", "user_password");
    log.info("Password setup login requested. identifier={}, bodyKeys={}", identifier, body == null ? "null" : body.keySet());
    return ApiResponse.ok(service.login(identifier, password), "Login successful.");
  }

  @PostMapping({"/register", "/signup", "/create-account"})
  public ApiResponse<Map<String, Object>> register(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body,
      HttpServletRequest request) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractParam(body, request, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to", "mail");
    String password = extractParam(body, request, "password", "rawPassword", "passcode", "secret", "pin", "newPassword", "user_password");
    String firstName = extractParam(body, request, "firstName", "first_name", "givenName", "given_name", "name");
    String lastName = extractParam(body, request, "lastName", "last_name", "familyName", "family_name", "surname");
    String phone = extractParam(body, request, "phoneNumber", "phone_number", "phone", "mobile");
    log.info("Password setup register requested. email={}, bodyKeys={}", email, body == null ? "null" : body.keySet());
    return ApiResponse.ok(service.register(uid, email, password, firstName, lastName, phone), "Account created successfully.");
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
        if (entry.getKey() != null) {
          String entryKey = String.valueOf(entry.getKey());
          if (entryKey.equalsIgnoreCase(key) && entry.getValue() != null) {
            String str = String.valueOf(entry.getValue()).trim();
            if (!str.isEmpty() && !str.equalsIgnoreCase("null")) {
              return str;
            }
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

