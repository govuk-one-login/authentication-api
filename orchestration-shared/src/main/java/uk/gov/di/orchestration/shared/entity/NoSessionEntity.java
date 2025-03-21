package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class NoSessionEntity {

    private final String clientSessionId;
    private final ErrorObject errorObject;
    private final OrchClientSessionItem orchClientSession;

    public NoSessionEntity(
            String clientSessionId,
            ErrorObject errorObject,
            OrchClientSessionItem orchClientSession) {
        this.clientSessionId = clientSessionId;
        this.errorObject = errorObject;
        this.orchClientSession = orchClientSession;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public OrchClientSessionItem getClientSession() {
        return orchClientSession;
    }
}
