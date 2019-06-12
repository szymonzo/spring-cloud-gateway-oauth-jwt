package de.nitrobox.gateway;

import static de.nitrobox.gateway.utils.JwtUtils.createValidatorsWith;
import static de.nitrobox.gateway.utils.JwtUtils.extractTenantIdFromAuthentication;
import static de.nitrobox.gateway.utils.JwtUtils.logTenantAndClientIdClaims;

import de.nitrobox.gateway.filters.TenantIdQueryParameterFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Slf4j
@Configuration
@EnableWebFluxSecurity
public class Routing {

  private static String TENANT_ID_HEADER_NAME = "X-Nitrobox-Tenant-Id";

  @Bean
  SecurityWebFilterChain authorization(ServerHttpSecurity security) {
    security
        .authorizeExchange()
        .anyExchange().authenticated()
        .and()
        .oauth2ResourceServer()
        .jwt();
    return security.build();
  }

  @Bean
  ReactiveJwtDecoder reactiveJwtDecoder(
      OAuth2ResourceServerProperties resourceServerProperties,
      SpringResourceServerValidationConfigurationProperties resourceServerValidationConfigurationProperties
  ) {
    var nimbusReactiveJwtDecoder = new NimbusReactiveJwtDecoder(
        resourceServerProperties.getJwt().getJwkSetUri());
    var validator = createValidatorsWith(
        resourceServerValidationConfigurationProperties.getIssuer(),
        resourceServerValidationConfigurationProperties.getAudiences());
    nimbusReactiveJwtDecoder.setJwtValidator(validator);
    return nimbusReactiveJwtDecoder;
  }

  @Bean
  public RouteLocator routeLocator(RouteLocatorBuilder builder,
      TenantIdQueryParameterFilter tenantIdQueryParameterFilter) {
    return builder.routes()
        .route(route -> route.path("/test")
            .filters(f -> f.addRequestHeader("X-Nitrobox", "MVP 4.0")
                .setPath("/get")
                .filter(tenantIdQueryParameterFilter
                    .apply(nameValueConfig -> nameValueConfig.setName("tenantId"))))
            .uri("http://httpbin.org"))
        .build();
  }

  @Bean
  public GlobalFilter tenantIdHeaderFilter() {
    return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
        .map(securityContext -> (JwtAuthenticationToken) securityContext.getAuthentication())
        .doOnNext(logTenantAndClientIdClaims())
        .map(jwtAuthenticationToken -> {
          String tenantId = extractTenantIdFromAuthentication(jwtAuthenticationToken);
          exchange.getRequest().mutate().header(TENANT_ID_HEADER_NAME, tenantId).build();
          return exchange;
        })
        .flatMap(chain::filter);
  }

}
