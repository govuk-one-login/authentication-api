package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.entity.ClientRegistry;

import java.util.List;
import java.util.Optional;

public interface ClientService {
    Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest);

    boolean isValidClient(String clientId);

    void addClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey);

    Optional<ClientRegistry> getClient(String clientId);

    ClientID generateClientID();
}
