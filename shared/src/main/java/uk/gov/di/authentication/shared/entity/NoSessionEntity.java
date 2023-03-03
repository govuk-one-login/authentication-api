package uk.gov.di.authentication.shared.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class NoSessionEntity {

    private final String clientSessionId;
    private final ErrorObject errorObject;
    private final ClientSession clientSession;

    public NoSessionEntity(
            String clientSessionId, ErrorObject errorObject, ClientSession clientSession) {
        this.clientSessionId = clientSessionId;
        this.errorObject = errorObject;
        this.clientSession = clientSession;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public ClientSession getClientSession() {
        return clientSession;
    }
}
