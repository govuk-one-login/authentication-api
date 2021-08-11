package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.UpdateClientConfigRequest;

import java.util.List;
import java.util.Optional;

public interface ClientService {

    boolean isValidClient(String clientId);

    void addClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris);

    Optional<ClientRegistry> getClient(String clientId);

    ClientID generateClientID();

    ClientRegistry updateClient(String clientId, UpdateClientConfigRequest updateRequest);
}
