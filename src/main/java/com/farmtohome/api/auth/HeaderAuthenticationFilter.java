package com.farmtohome.api.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class HeaderAuthenticationFilter extends OncePerRequestFilter {
  private final JwtUtil jwtUtil;

  public HeaderAuthenticationFilter(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authorization = request.getHeader("Authorization");
    String uid = null;

    if (authorization != null && authorization.startsWith("Bearer ")) {
      String rawToken = authorization.substring(7).trim();
      uid = jwtUtil.extractUid(rawToken);
    } else {
      String userIdHeader = request.getHeader("X-User-Id");
      if (userIdHeader != null && !userIdHeader.isBlank()) {
        uid = userIdHeader.trim();
      }
    }

    if (uid == null || uid.isBlank()) {
      uid = "dev_user";
    }

    var authorities = List.of(
        new SimpleGrantedAuthority("ROLE_USER"),
        new SimpleGrantedAuthority("ROLE_ADMIN"));
    var authentication = new UsernamePasswordAuthenticationToken(uid, null, authorities);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    filterChain.doFilter(request, response);
  }
}

