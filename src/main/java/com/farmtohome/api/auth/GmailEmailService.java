package com.farmtohome.api.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class GmailEmailService {
  private static final Logger log = LoggerFactory.getLogger(GmailEmailService.class);

  private final JavaMailSender mailSender;
  private final String host;
  private final int port;
  private final String configuredUsername;
  private final String configuredPassword;
  private final String mailFrom;
  private final String resendApiKey;
  private final String resendFrom;

  public GmailEmailService(
      JavaMailSender mailSender,
      @Value("${spring.mail.host:smtp.gmail.com}") String host,
      @Value("${spring.mail.port:587}") int port,
      @Value("${spring.mail.username:mail.farmtohomef@gmail.com}") String username,
      @Value("${spring.mail.password:ozwykgdylurdgsqb}") String password,
      @Value("${app.mail-from:mail.farmtohomef@gmail.com}") String mailFrom,
      @Value("${RESEND_API_KEY:${app.resend-api-key:${resend.api.key:${RESEND_KEY:}}}}") String resendApiKey,
      @Value("${RESEND_FROM:${app.resend-from:${resend.from:onboarding@resend.dev}}}") String resendFrom) {
    this.mailSender = mailSender;
    this.host = host == null ? "smtp.gmail.com" : host.trim();
    this.port = port;
    this.configuredUsername = username == null ? "mail.farmtohomef@gmail.com" : username.trim();
    this.configuredPassword = password == null ? "ozwykgdylurdgsqb" : password.trim();
    this.mailFrom = mailFrom == null ? "mail.farmtohomef@gmail.com" : mailFrom.trim();
    this.resendApiKey = resendApiKey == null ? "" : resendApiKey.trim();
    this.resendFrom = resendFrom == null ? "onboarding@resend.dev" : resendFrom.trim();
  }

  @PostConstruct
  public void logStartupInfo() {
    log.info("================ Email Service Configuration ================");
    log.info("Resend HTTP API key present: {}", !resendApiKey.isEmpty());
    if (!resendApiKey.isEmpty()) {
      log.info("Resend API Key prefix: {}...", resendApiKey.substring(0, Math.min(6, resendApiKey.length())));
    } else {
      log.warn("RESEND_API_KEY is NOT set in Railway environment variables. Add RESEND_API_KEY to Railway variables to enable instant email delivery.");
    }
    log.info("Resend Sender (RESEND_FROM): {}", resendFrom);
    log.info("Gmail SMTP host: {}", host);
    log.info("Gmail SMTP port: {}", port);
    log.info("Gmail SMTP configured username: {}", configuredUsername);
    log.info("Gmail Sender (MAIL_FROM): {}", mailFrom);
    log.info("=============================================================");
  }

  public boolean sendOtpEmail(String toEmail, String otp, String subject, String messageType) {
    log.info("Generated {} OTP for [{}]: {}", messageType, toEmail, otp);

    String textContent = String.format(
        "Your Farm To Home %s OTP is: %s\n\nThis OTP expires in 5 minutes.\nDo not share this OTP with anyone.",
        messageType, otp);

    // 1. Try Resend HTTP REST API (Port 443 - Fast & Cloud Firewall safe)
    if (!resendApiKey.isEmpty()) {
      if (tryResendApi(toEmail, otp, subject, textContent)) {
        return true;
      }
    } else {
      log.warn("RESEND_API_KEY environment variable is not configured in Railway. Outbound Resend HTTP API skipped.");
    }

    // 2. Fallback to Gmail SMTP with strict 2-second timeout
    String cleanPassword = configuredPassword.replaceAll("\\s+", "");
    String[] candidateUsernames = new String[] { configuredUsername };
    String[] candidatePasswords = new String[] { cleanPassword };

    Exception lastException = null;

    for (String user : candidateUsernames) {
      if (user == null || user.isBlank()) continue;
      for (String pwd : candidatePasswords) {
        if (pwd == null || pwd.isBlank()) continue;

        try {
          JavaMailSenderImpl impl;
          if (mailSender instanceof JavaMailSenderImpl jImpl) {
            impl = jImpl;
          } else {
            impl = new JavaMailSenderImpl();
          }

          impl.setHost(host);
          impl.setPort(port);
          impl.setUsername(user);
          impl.setPassword(pwd);

          java.util.Properties props = impl.getJavaMailProperties();
          props.put("mail.smtp.auth", "true");
          props.put("mail.smtp.starttls.enable", "true");
          props.put("mail.smtp.starttls.required", "true");
          props.put("mail.smtp.ssl.trust", "smtp.gmail.com");
          props.put("mail.smtp.connectiontimeout", "2000");
          props.put("mail.smtp.timeout", "2000");
          props.put("mail.smtp.writetimeout", "2000");

          MimeMessage message = impl.createMimeMessage();
          MimeMessageHelper helper = new MimeMessageHelper(message, StandardCharsets.UTF_8.name());
          helper.setFrom(user);
          helper.setTo(toEmail);
          helper.setSubject(subject);
          helper.setText(textContent, false);

          log.info("Attempting Gmail SMTP send with account [{}]...", user);
          impl.send(message);
          log.info("Successfully delivered OTP email to {} via Gmail SMTP using account [{}]", toEmail, user);
          return true;
        } catch (Exception ex) {
          log.warn("Gmail SMTP attempt failed for account [{}]: {}", user, ex.getMessage());
          lastException = ex;
        }
      }
    }

    log.error("All email delivery attempts failed for recipient {}: {}", toEmail, lastException != null ? lastException.getMessage() : "No active provider succeeded");
    return false;
  }

  private boolean tryResendApi(String toEmail, String otp, String subject, String textContent) {
    try {
      String jsonBody = String.format(
          "{\"from\":\"%s\",\"to\":[\"%s\"],\"subject\":\"%s\",\"text\":\"%s\"}",
          escapeJson(resendFrom),
          escapeJson(toEmail),
          escapeJson(subject),
          escapeJson(textContent));

      HttpClient client = HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(4))
          .build();

      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create("https://api.resend.com/emails"))
          .header("Authorization", "Bearer " + resendApiKey)
          .header("Content-Type", "application/json")
          .timeout(Duration.ofSeconds(4))
          .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
          .build();

      log.info("Attempting Resend HTTP REST API delivery to [{}]...", toEmail);
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() >= 200 && response.statusCode() < 300) {
        log.info("Successfully delivered OTP email to {} via Resend HTTP API. Status: {}", toEmail, response.statusCode());
        return true;
      } else {
        log.error("Resend HTTP API returned failure status {}: {}", response.statusCode(), response.body());
      }
    } catch (Exception ex) {
      log.error("Resend HTTP API delivery attempt failed for recipient {}: {}", toEmail, ex.getMessage(), ex);
    }
    return false;
  }

  private String escapeJson(String input) {
    if (input == null) return "";
    return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
  }
}
