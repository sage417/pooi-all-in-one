package app.pooi.workflow.infrastructure.configuration.keycloak;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("keycloak")
public class KeycloakClientProperties {

    private String serverUrl;

    private String realm;

    private String clientId;

    private String clientSecret;

    private String grantType;
}
