package de.nitrobox.gateway.filters;

import de.nitrobox.gateway.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AddRequestParameterGatewayFilterFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TenantIdQueryParameterFilter extends AddRequestParameterGatewayFilterFactory {

  @Override
  public GatewayFilter apply(NameValueConfig config) {
    return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
        .map(securityContext -> (JwtAuthenticationToken) securityContext.getAuthentication())
        .doOnNext(JwtUtils.logTenantAndClientIdClaims())
        .map(JwtUtils::extractTenantIdFromAuthentication)
        .flatMap(tenantId -> super.apply(config.setValue(tenantId)).filter(exchange, chain));
  }
}
