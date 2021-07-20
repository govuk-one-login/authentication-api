package uk.gov.di.exceptions;

import static java.lang.String.format;

public class ClientNotFoundException extends Exception {

    public ClientNotFoundException(String clientID) {
        super(format("No Client found for ClientID: %s", clientID));
    }
}
