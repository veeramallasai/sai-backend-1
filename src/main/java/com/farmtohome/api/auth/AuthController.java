package com.farmtohome.api.auth;

import com.farmtohome.api.common.ApiResponse;
import java.security.Principal;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/auth", "/auth"})
public class AuthController {
  private static final Logger log = LoggerFactory.getLogger(AuthController.class);
  private final PasswordSetupService service;

  public AuthController(PasswordSetupService service) {
    this.service = service;
  }

  @PostMapping({"/login", "/password-login", "/login-password"})
  public ApiResponse<Map<String, Object>> login(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body) {
    String identifier = extractString(body, "email", "identifier", "username", "targetEmail", "user_email", "phone", "phoneNumber", "mobile");
    String password = extractString(body, "password", "rawPassword", "passcode", "secret", "pin", "newPassword");
    log.info("Auth login requested. identifier={}, bodyKeys={}", identifier, body == null ? "null" : body.keySet());
    return ApiResponse.ok(service.login(identifier, password), "Login successful.");
  }

  @PostMapping({"/register", "/signup", "/create-account", "/register-user", "/user-register"})
  public ApiResponse<Map<String, Object>> register(
      Principal principal,
      @RequestBody(required = false) Map<String, Object> body) {
    String uid = principal == null ? "dev_user" : principal.getName();
    String email = extractString(body, "email", "targetEmail", "userEmail", "user_email", "target_email", "emailAddress", "email_address", "username", "identifier", "recipient", "to");
    String password = extractString(body, "password", "rawPassword", "passcode", "secret", "pin", "newPassword", "user_password");
    String firstName = extractString(body, "firstName", "first_name", "givenName", "given_name", "name");
    String lastName = extractString(body, "lastName", "last_name", "familyName", "family_name", "surname");
    String phone = extractString(body, "phoneNumber", "phone_number", "phone", "mobile");
    log.info("Auth register requested. email={}, bodyKeys={}", email, body == null ? "null" : body.keySet());
    return ApiResponse.ok(service.register(uid, email, password, firstName, lastName, phone), "Account created successfully.");
  }

  private String extractString(Map<String, Object> map, String... keys) {
    if (map == null) return null;
    for (String key : keys) {
      for (Map.Entry<String, Object> entry : map.entrySet()) {
        if (entry.getKey().equalsIgnoreCase(key) && entry.getValue() != null) {
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
