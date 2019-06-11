package de.nitrobox.gateway;

import de.nitrobox.gateway.filters.TenantIdQueryParameterFilter;
import de.nitrobox.gateway.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
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
        .jwt()
        .jwkSetUri("http://localhost:8080/.well-known/jwks.json");
    return security.build();
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
        .doOnNext(JwtUtils.logTenantAndClientIdClaims())
        .map(jwtAuthenticationToken -> {
          String tenantId = JwtUtils.extractTenantIdFromAuthentication(jwtAuthenticationToken);
          exchange.getRequest().mutate().header(TENANT_ID_HEADER_NAME, tenantId).build();
          return exchange;
        })
        .flatMap(chain::filter);
  }

}
