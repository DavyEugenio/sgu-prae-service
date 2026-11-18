package br.edu.ufape.sguPraeService.config;

import br.edu.ufape.sguPraeService.servicos.interfaces.KeycloakService;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * Sincronizador automático de ambiente local/testes ('dev' e 'docker').
 * Garante que jamais haja inconsistência entre o 'keycloak.client-secret' configurado na aplicação
 * e o secret armazenado no banco do Keycloak local — mesmo que:
 * 1. O desenvolvedor já possua um volume Docker antigo ('keycloak-pg-data') criado antes da remoção do secret hardcoded;
 * 2. O 'realm-export.json' tenha sido importado manualmente pela interface web sem expandir '${KEYCLOAK_CLIENT_SECRET}';
 * 3. O desenvolvedor altere 'KEYCLOAK_CLIENT_SECRET' sem recriar os volumes do banco.
 *
 * Nunca é carregado em produção (@Profile({"dev", "docker"})).
 */
@Slf4j
@Component
@Profile({"dev", "docker"})
@RequiredArgsConstructor
public class KeycloakDevEnvironmentSynchronizer implements ApplicationRunner {

    private final KeycloakService keycloakService;

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String expectedClientSecret;

    @Value("${keycloak.admin-username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin-password:admin}")
    private String adminPassword;

    @Value("${keycloak.dev-admin-enabled:true}")
    private boolean devAdminEnabled;

    @Value("${keycloak.dev-admin-email:admin@ufape.edu.br}")
    private String devAdminEmail;

    @Value("${keycloak.dev-admin-password:Admin@123}")
    private String devAdminPassword;

    @Override
    public void run(ApplicationArguments args) {
        try (Keycloak adminKeycloak = createAdminClient()) {
            syncClientSecret(adminKeycloak);
            ensureDevSslMode(adminKeycloak);
            if (devAdminEnabled) {
                ensureDevAdminExists(adminKeycloak);
            }
        } catch (Exception e) {
            log.debug("Sincronização automática do Keycloak local ignorada (Keycloak offline ou em ambiente de teste isolado): {}", e.getMessage());
        }
    }

    private void syncClientSecret(Keycloak adminKeycloak) {
        List<ClientRepresentation> clients = adminKeycloak.realm(realm).clients().findByClientId(clientId);
        if (clients == null || clients.isEmpty()) {
            log.debug("Client '{}' não encontrado no realm '{}' durante verificação de sincronia local.", clientId, realm);
            return;
        }

        ClientRepresentation clientRep = clients.getFirst();
        ClientResource clientResource = adminKeycloak.realm(realm).clients().get(clientRep.getId());
        CredentialRepresentation secretCredential = clientResource.getSecret();
        String currentSecretInKeycloak = secretCredential != null ? secretCredential.getValue() : clientRep.getSecret();

        if (!expectedClientSecret.equals(currentSecretInKeycloak)) {
            clientRep.setSecret(expectedClientSecret);
            clientResource.update(clientRep);
            keycloakService.init();
            log.info("Auto-Heal [dev/docker]: Client secret do client '{}' foi sincronizado automaticamente no Keycloak local.", clientId);
        } else {
            log.debug("Client secret do client '{}' já está sincronizado no Keycloak local.", clientId);
        }
    }

    private void ensureDevSslMode(Keycloak adminKeycloak) {
        try {
            RealmRepresentation realmRep = adminKeycloak.realm(realm).toRepresentation();
            if (realmRep != null && realmRep.getSslRequired() != null
                    && !"none".equalsIgnoreCase(realmRep.getSslRequired())) {
                realmRep.setSslRequired("none");
                adminKeycloak.realm(realm).update(realmRep);
                log.info("Auto-Heal [dev/docker]: 'sslRequired' ajustado para 'none' no realm '{}' para suportar acessos HTTP locais/LAN.", realm);
            }
        } catch (Exception e) {
            log.debug("Ajuste automático de sslRequired ignorado: {}", e.getMessage());
        }
    }

    private void ensureDevAdminExists(Keycloak adminKeycloak) {
        if (devAdminEmail == null || devAdminEmail.isBlank() || devAdminPassword == null || devAdminPassword.isBlank()) {
            return;
        }
        try {
            List<UserRepresentation> adminsExistentes = adminKeycloak.realm(realm)
                    .roles().get("administrador").getUserMembers(0, 1);
            if (adminsExistentes != null && !adminsExistentes.isEmpty()) {
                log.debug("Realm '{}' já possui usuário com role 'administrador'. Bootstrap ignorado.", realm);
                return;
            }

            List<UserRepresentation> found = adminKeycloak.realm(realm).users().searchByEmail(devAdminEmail, true);
            String userId;
            if (found != null && !found.isEmpty()) {
                UserRepresentation existing = found.getFirst();
                userId = existing.getId();
                existing.setEnabled(true);
                existing.setEmailVerified(true);
                existing.setRequiredActions(Collections.emptyList());
                if (existing.getFirstName() == null || existing.getFirstName().isBlank()) {
                    existing.setFirstName("Administrador");
                }
                if (existing.getLastName() == null || existing.getLastName().isBlank()) {
                    existing.setLastName("Sistema");
                }
                adminKeycloak.realm(realm).users().get(userId).update(existing);
            } else {
                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setTemporary(false);
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue(devAdminPassword);

                UserRepresentation adminUser = new UserRepresentation();
                adminUser.setUsername(devAdminEmail);
                adminUser.setEmail(devAdminEmail);
                adminUser.setFirstName("Administrador");
                adminUser.setLastName("Sistema");
                adminUser.setEnabled(true);
                adminUser.setEmailVerified(true);
                adminUser.setRequiredActions(Collections.emptyList());
                adminUser.setCredentials(Collections.singletonList(credential));

                try (Response response = adminKeycloak.realm(realm).users().create(adminUser)) {
                    if (response.getStatus() != 201) {
                        log.warn("Não foi possível criar usuário administrador bootstrap no Keycloak (status={}).", response.getStatus());
                        return;
                    }
                    userId = CreatedResponseUtil.getCreatedId(response);
                }
            }

            RoleRepresentation adminRole = adminKeycloak.realm(realm).roles().get("administrador").toRepresentation();
            adminKeycloak.realm(realm).users().get(userId).roles().realmLevel().add(Collections.singletonList(adminRole));
            log.info("Bootstrap [dev/docker]: Usuário administrador '{}' garantido no realm '{}' com e-mail verificado e senha definitiva.", devAdminEmail, realm);
        } catch (Exception e) {
            log.warn("Bootstrap de administrador local não concluído: {}", e.getMessage());
        }
    }

    protected Keycloak createAdminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(keycloakServerUrl)
                .realm("master")
                .clientId("admin-cli")
                .username(adminUsername)
                .password(adminPassword)
                .grantType("password")
                .build();
    }
}
