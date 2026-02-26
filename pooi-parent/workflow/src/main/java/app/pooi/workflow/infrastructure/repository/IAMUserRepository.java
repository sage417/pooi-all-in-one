package app.pooi.workflow.infrastructure.repository;


import app.pooi.workflow.domain.model.IAMUser;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.BooleanUtils;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class IAMUserRepository implements app.pooi.workflow.domain.repository.IAMUserRepository {

    private final Keycloak keycloakClient;

    @Value("${keycloak.realm}")
    private String realm;

    private IAMUser convertToDomain(UserRepresentation userRepresentation) {
        return IAMUser.builder()
                .id(userRepresentation.getId())
                .username(userRepresentation.getUsername())
                .email(userRepresentation.getEmail())
                .firstName(userRepresentation.getFirstName())
                .lastName(userRepresentation.getLastName())
                .emailVerified(BooleanUtils.isTrue(userRepresentation.isEmailVerified()))
                .attributes(userRepresentation.getAttributes())
                .build();
    }

    @Override
    public Optional<IAMUser> findByUsername(String username) {
        List<UserRepresentation> userList = keycloakClient.realm(realm)
                .users()
                .search(username);
        return userList.stream()
                .findFirst()
                .map(this::convertToDomain);
    }

    @Override
    public List<IAMUser> findAll(int first, int max) {
        return keycloakClient.realm(realm)
                .users()
                .list(first, max)
                .stream()
                .map(this::convertToDomain)
                .collect(Collectors.toList());
    }

    @Override
    public Optional<IAMUser> findById(String userId) {
        try {
            UserRepresentation user = keycloakClient.realm(realm)
                    .users()
                    .get(userId)
                    .toRepresentation();
            return Optional.of(convertToDomain(user));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
