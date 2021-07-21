package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.exceptions.ClientNotFoundException;

import java.net.URI;
import java.util.Optional;

public class AuthorizationService {

    private final DynamoClientService dynamoClientService;

    public AuthorizationService(DynamoClientService dynamoClientService) {
        this.dynamoClientService = dynamoClientService;
    }

    public AuthorizationService(ConfigurationService configurationService) {
        this(
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri()));
    }

    public boolean isClientRedirectUriValid(ClientID clientID, URI redirectURI)
            throws ClientNotFoundException {
        Optional<ClientRegistry> client = dynamoClientService.getClient(clientID.toString());
        if (client.isEmpty()) {
            throw new ClientNotFoundException(clientID.toString());
        }
        return client.get().getRedirectUrls().contains(redirectURI.toString());
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthorizationRequest authRequest, AuthorizationCode authorizationCode) {
        return new AuthenticationSuccessResponse(
                authRequest.getRedirectionURI(),
                authorizationCode,
                null,
                null,
                authRequest.getState(),
                null,
                authRequest.getResponseMode());
    }
}
