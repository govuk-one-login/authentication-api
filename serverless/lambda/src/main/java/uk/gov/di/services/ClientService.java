package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.entity.ClientRegistry;

import java.util.List;
import java.util.Optional;

public interface ClientService {
    Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest);

    boolean isValidClient(String clientId);

    ClientRegistry addClient(String clientName, List<String> redirectUris, List<String> contacts);

    Optional<ClientRegistry> getClient(String clientId);
}
