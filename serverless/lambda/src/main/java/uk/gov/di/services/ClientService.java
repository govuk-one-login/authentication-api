package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import uk.gov.di.entity.Client;

import java.util.List;
import java.util.Optional;

public interface ClientService {
    Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest);

    AuthenticationResponse getSuccessfulResponse(AuthenticationRequest authRequest, String email);

    boolean isValidClient(String clientId, String clientSecret);

    Client addClient(String clientName, List<String> redirectUris, List<String> contacts);

    Optional<Client> getClient(String clientId);
}
