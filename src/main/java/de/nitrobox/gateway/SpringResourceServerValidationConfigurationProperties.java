package de.nitrobox.gateway;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.resourceserver.validation")
public class SpringResourceServerValidationConfigurationProperties {

  private List<String> audiences = new ArrayList<>();

  private String issuer = "";

}
