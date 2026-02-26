package app.pooi.workflow.infrastructure.configuration.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties(KeycloakClientProperties.class)
@Configuration
public class KeyCloakConfiguration {

    @Bean
    public Keycloak keycloakClient(KeycloakClientProperties properties) {
        return KeycloakBuilder.builder()
                .serverUrl(properties.getServerUrl())
                .realm(properties.getRealm())
                .clientId(properties.getClientId())
                .clientSecret(properties.getClientSecret())
                .grantType(properties.getGrantType())
                .build();
    }
}
