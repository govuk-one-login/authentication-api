package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.OIDCError;
import uk.gov.di.entity.ClientRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class InMemoryClientService implements ClientService {

    private final List<ClientRegistry> clientRegistry =
            new ArrayList<>() {
                {
                    add(
                            new ClientRegistry()
                                    .setClientName("client-name")
                                    .setClientID("test-id")
                                    .setRedirectUrls(
                                            List.of(
                                                    "http://localhost:8081/oidc/callback",
                                                    "http://localhost:3000/",
                                                    "https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/callback"))
                                    .setContacts(List.of("contact@example.com")));
                }
            };

    public InMemoryClientService() {}

    @Override
    public Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest) {
        Optional<ClientRegistry> clientMaybe = getClient(authRequest.getClientID().toString());

        if (clientMaybe.isEmpty()) {
            return Optional.of(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS);
        }
        return Optional.empty();
    }

    @Override
    public boolean isValidClient(String clientId) {
        Optional<ClientRegistry> client = getClient(clientId);
        return client.isPresent();
    }

    @Override
    public ClientRegistry addClient(
            String clientName, List<String> redirectUris, List<String> contacts) {
        String clientId = UUID.randomUUID().toString();
        ClientRegistry client =
                new ClientRegistry()
                        .setClientID(clientId)
                        .setClientName(clientName)
                        .setRedirectUrls(redirectUris)
                        .setContacts(contacts)
                        .setPublicKey("")
                        .setClientFriendlyName("");
        clientRegistry.add(client);
        return client;
    }

    @Override
    public Optional<ClientRegistry> getClient(String clientId) {
        return clientRegistry.stream().filter(t -> t.getClientID().equals(clientId)).findFirst();
    }
}
