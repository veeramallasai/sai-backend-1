package com.farmtohome.api.auth;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class PasswordSetupDtos {
  private PasswordSetupDtos() {}

  public record SendRequest(
      @NotBlank(message = "Email address is required.")
      @Email(message = "Enter a valid email address.")
      String email) {}

  public record VerifyRequest(
      String email,
      @NotBlank(message = "OTP is required.")
      @Pattern(regexp = "\\d{6}", message = "OTP must be 6 digits.")
      String otp) {}

  public record ResetPasswordRequest(
      String email,
      @NotBlank(message = "OTP is required.")
      @Pattern(regexp = "\\d{6}", message = "OTP must be 6 digits.")
      String otp,
      @NotBlank(message = "Password is required.")
      @Size(min = 6, message = "Password must be at least 6 characters.")
      @JsonAlias({"newPassword", "new_password"})
      String password) {}
}
