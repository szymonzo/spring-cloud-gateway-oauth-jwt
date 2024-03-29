package de.nitrobox.gateway.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@Slf4j
public class JwtUtils {

  private static final String TENANT_ID_CLAIM_NAME = "tenantId";
  private static final String CLIENT_ID_CLAIM_NAME = "client_id";
  private static final String UNKNOWN_FALLBACK = "unknown";

  public static String extractTenantIdFromAuthentication(
      JwtAuthenticationToken jwtAuthenticationToken) {
    return (String) jwtAuthenticationToken.getTokenAttributes()
        .getOrDefault(TENANT_ID_CLAIM_NAME, UNKNOWN_FALLBACK);
  }

  private static String extractClientIdFromAuthentication(
      JwtAuthenticationToken jwtAuthenticationToken) {
    return (String) jwtAuthenticationToken.getTokenAttributes()
        .getOrDefault(CLIENT_ID_CLAIM_NAME, "unknown");

  }

  public static Consumer<JwtAuthenticationToken> logTenantAndClientIdClaims() {
    return jwtAuthenticationToken -> {
      var tenantId = extractTenantIdFromAuthentication(jwtAuthenticationToken);
      var clientId = extractClientIdFromAuthentication(jwtAuthenticationToken);
      log.info("Request client id {} and tenant id {}", clientId, tenantId);
    };
  }

  public static OAuth2TokenValidator<Jwt> createValidatorsWith(String issuer,
      List<String> audiences) {
    List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
    validators.add(new JwtTimestampValidator());
    validators.add(new JwtIssuerValidator(issuer));
    validators.add(new JwtAudienceValidator(audiences));
    return new DelegatingOAuth2TokenValidator<>(validators);
  }

}
