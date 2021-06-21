package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.OIDCError;
import uk.gov.di.entity.Client;
import uk.gov.di.helpers.AuthenticationResponseHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class InMemoryClientService implements ClientService {

    private List<Client> clients =
            new ArrayList<>() {
                {
                    add(
                            new Client(
                                    "client-name",
                                    "test-id",
                                    "test-secret",
                                    List.of("code"),
                                    List.of("http://localhost:8080", "https://di-auth-stub-relying-party-build.london.cloudapps.digital"),
                                    List.of("contact@example.com")));
                }
            };

    private AuthorizationCodeService authorizationCodeService;

    public InMemoryClientService(AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
    }

    @Override
    public Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest) {
        Optional<Client> clientMaybe = getClient(authRequest.getClientID().toString());

        if (clientMaybe.isEmpty()) {
            return Optional.of(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS);
        }

        var client = clientMaybe.get();

        if (!client.getRedirectUris().contains(authRequest.getRedirectionURI().toString())) {
            return Optional.of(OAuth2Error.INVALID_REQUEST_URI);
        }

        if (!client.getAllowedResponseTypes().contains(authRequest.getResponseType().toString())) {
            return Optional.of(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
        }

        return Optional.empty();
    }

    @Override
    public AuthenticationResponse getSuccessfulResponse(
            AuthenticationRequest authRequest, String email) {
        AuthorizationCode code = authorizationCodeService.issueCodeForUser(email);
        return AuthenticationResponseHelper.generateSuccessfulAuthResponse(authRequest, code);
    }

    @Override
    public boolean isValidClient(String clientId, String clientSecret) {
        Optional<Client> client = getClient(clientId);
        return client.map(c -> c.getClientSecret().equals(clientSecret)).orElse(false);
    }

    @Override
    public Client addClient(String clientName, List<String> redirectUris, List<String> contacts) {

        String clientId = UUID.randomUUID().toString();
        String clientSecret = UUID.randomUUID().toString();
        Client client =
                new Client(
                        clientName,
                        clientId,
                        clientSecret,
                        List.of("code"),
                        redirectUris,
                        contacts);
        clients.add(client);
        return client;
    }

    @Override
    public Optional<Client> getClient(String clientId) {
        return clients.stream().filter(t -> t.getClientId().equals(clientId)).findFirst();
    }
}
