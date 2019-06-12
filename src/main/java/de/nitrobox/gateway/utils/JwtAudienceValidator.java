package de.nitrobox.gateway.utils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {

  private static OAuth2Error INVALID_AUDIENCE =
      new OAuth2Error(
          OAuth2ErrorCodes.INVALID_REQUEST,
          "Audiences claim is not equal to the configured audience",
          "https://tools.ietf.org/html/rfc7519#section-4.1.3");

  private final Set<String> givenAudiences;

  JwtAudienceValidator(Collection<String> audience) {
    this.givenAudiences = new HashSet<>(audience);
  }

  @Override
  public OAuth2TokenValidatorResult validate(Jwt token) {
    var jwtAudiences = token.getAudience();
    var intersection = CollectionUtils.intersection(givenAudiences, jwtAudiences);
    if (givenAudiences.size() != intersection.size()) {
      return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
    }
    return OAuth2TokenValidatorResult.success();
  }
}
