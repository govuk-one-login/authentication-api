package uk.gov.di.orchestration.shared.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import static java.lang.String.format;

public class TokenAuthInvalidException extends Exception {

    private final ErrorObject errorObject;
    private final String clientId;

    public TokenAuthInvalidException(
            ErrorObject errorObject,
            ClientAuthenticationMethod clientAuthenticationMethod,
            String clientID) {
        super(
                format(
                        "Issue when validating %s for clientID: %s. Reason: %s",
                        clientAuthenticationMethod.getValue(),
                        clientID,
                        errorObject.getDescription()));
        this.errorObject = errorObject;
        this.clientId = clientID;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public String getClientId() {
        return clientId;
    }
}
