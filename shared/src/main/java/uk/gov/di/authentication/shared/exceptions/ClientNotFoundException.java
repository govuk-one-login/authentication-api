package uk.gov.di.authentication.shared.exceptions;

import uk.gov.di.authentication.shared.entity.Session;

import static java.lang.String.format;

public class ClientNotFoundException extends Exception {

    public ClientNotFoundException(String clientID) {
        super(format("No Client found for ClientID: %s", clientID));
    }

    public ClientNotFoundException(Session session) {
        super(format("No Client found for SessionId: %s", session.getSessionId()));
    }
}
