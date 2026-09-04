package com.farmtohome.api.common;

import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(ApiException.class)
  ResponseEntity<Map<String, Object>> api(ApiException error) {
    return ResponseEntity.status(error.status()).body(Map.of(
        "success", false,
        "message", error.getMessage(),
        "code", error.status().name()));
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ResponseEntity<Map<String, Object>> validation(MethodArgumentNotValidException error) {
    String message = error.getBindingResult().getFieldErrors().stream()
        .map(value -> value.getField() + ": " + value.getDefaultMessage())
        .collect(Collectors.joining(", "));
    return ResponseEntity.badRequest().body(Map.of(
        "success", false, "message", message, "code", "VALIDATION_ERROR"));
  }

  @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
  ResponseEntity<Map<String, Object>> bodyNotReadable(org.springframework.http.converter.HttpMessageNotReadableException error) {
    return ResponseEntity.badRequest().body(Map.of(
        "success", false, "message", "Required request body is missing or malformed.", "code", "BAD_REQUEST"));
  }

  @ExceptionHandler(AccessDeniedException.class)
  ResponseEntity<Map<String, Object>> denied(AccessDeniedException error) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
        "success", false, "message", "Access denied.", "code", "FORBIDDEN"));
  }

  @ExceptionHandler(org.springframework.dao.DataAccessException.class)
  ResponseEntity<Map<String, Object>> dataAccess(org.springframework.dao.DataAccessException error) {
    log.error("Database access exception", error);
    return ResponseEntity.badRequest().body(Map.of(
        "success", false,
        "message", "Database operation failed. Please check input data and try again.",
        "code", "BAD_REQUEST"));
  }

  @ExceptionHandler({IllegalArgumentException.class, NullPointerException.class})
  ResponseEntity<Map<String, Object>> illegalArgumentOrNull(RuntimeException error) {
    log.error("Request processing exception", error);
    return ResponseEntity.badRequest().body(Map.of(
        "success", false,
        "message", error.getMessage() != null ? error.getMessage() : "Invalid request input.",
        "code", "BAD_REQUEST"));
  }

  @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
  ResponseEntity<Map<String, Object>> noResource(org.springframework.web.servlet.resource.NoResourceFoundException error) {
    log.warn("Resource/Endpoint not found: {}", error.getResourcePath());
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
        "success", false,
        "message", "Endpoint not found: " + error.getResourcePath(),
        "code", "NOT_FOUND"));
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<Map<String, Object>> unexpected(Exception error) {
    log.error("Unhandled API exception", error);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
        "success", false,
        "message", error.getMessage() != null && !error.getMessage().isBlank() ? error.getMessage() : "Unable to complete the request.",
        "code", "INTERNAL_ERROR"));
  }
}
