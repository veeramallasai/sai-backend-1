package com.farmtohome.api.auth;

import java.nio.charset.StandardCharsets;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import com.farmtohome.api.common.ApiException;

@Service
public class GmailEmailService {
  private static final Logger log = LoggerFactory.getLogger(GmailEmailService.class);

  private final JavaMailSender mailSender;
  private final String host;
  private final int port;
  private final String configuredUsername;
  private final String configuredPassword;
  private final String mailFrom;

  public GmailEmailService(
      JavaMailSender mailSender,
      @Value("${spring.mail.host:smtp.gmail.com}") String host,
      @Value("${spring.mail.port:587}") int port,
      @Value("${spring.mail.username:mail.farmtohomef@gmail.com}") String username,
      @Value("${spring.mail.password:ozwykgdylurdgsqb}") String password,
      @Value("${app.mail-from:mail.farmtohomef@gmail.com}") String mailFrom) {
    this.mailSender = mailSender;
    this.host = host == null ? "smtp.gmail.com" : host.trim();
    this.port = port;
    this.configuredUsername = username == null ? "mail.farmtohomef@gmail.com" : username.trim();
    this.configuredPassword = password == null ? "ozwykgdylurdgsqb" : password.trim();
    this.mailFrom = mailFrom == null ? "mail.farmtohomef@gmail.com" : mailFrom.trim();
  }

  @PostConstruct
  public void logStartupInfo() {
    log.info("================ Gmail SMTP Configuration ================");
    log.info("Gmail SMTP host: {}", host);
    log.info("Gmail SMTP port: {}", port);
    log.info("Gmail SMTP configured username: {}", configuredUsername);
    log.info("Gmail SMTP password length: {}", configuredPassword.replaceAll("\\s+", "").length());
    log.info("Gmail Sender (MAIL_FROM): {}", mailFrom);
    log.info("==========================================================");
  }

  public boolean sendOtpEmail(String toEmail, String otp, String subject, String messageType) {
    log.info("Generated {} OTP for [{}]: {}", messageType, toEmail, otp);

    String cleanPassword = configuredPassword.replaceAll("\\s+", "");
    String spacedPassword = cleanPassword.replaceAll(".{4}", "$0 ").trim();

    String[] candidateUsernames = new String[] {
        configuredUsername,
        "farmtohomef@gmail.com",
        "mail.farmtohomef@gmail.com"
    };

    String[] candidatePasswords = new String[] {
        cleanPassword,
        spacedPassword
    };

    String textContent = String.format(
        "Your Farm To Home %s OTP is: %s\n\nThis OTP expires in 5 minutes.\nDo not share this OTP with anyone.",
        messageType, otp);

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
          props.put("mail.smtp.connectiontimeout", "10000");
          props.put("mail.smtp.timeout", "10000");
          props.put("mail.smtp.writetimeout", "10000");

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

    log.error("All Gmail SMTP delivery attempts failed for recipient {}", toEmail, lastException);
    throw new ApiException(
        HttpStatus.BAD_REQUEST,
        "Gmail SMTP Authentication/Delivery failed: " + (lastException == null ? "Unknown error" : lastException.getMessage()));
  }
}
