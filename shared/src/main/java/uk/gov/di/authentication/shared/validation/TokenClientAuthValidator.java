package uk.gov.di.authentication.shared.validation;

import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Map;

public abstract class TokenClientAuthValidator {

    protected final Logger LOG = LogManager.getLogger(this.getClass());
    protected final DynamoClientService dynamoClientService;

    protected TokenClientAuthValidator(DynamoClientService dynamoClientService) {
        this.dynamoClientService = dynamoClientService;
    }

    public abstract ClientRegistry validateTokenAuthAndReturnClientRegistryIfValid(
            String requestBody, Map<String, String> requestHeaders)
            throws TokenAuthInvalidException;

    protected ClientRegistry getClientRegistryFromTokenAuth(ClientID clientID)
            throws InvalidClientException {
        return dynamoClientService
                .getClient(clientID.getValue())
                .orElseThrow(
                        () ->
                                new InvalidClientException(
                                        "Invalid ClientID: " + clientID.getValue()));
    }
}
