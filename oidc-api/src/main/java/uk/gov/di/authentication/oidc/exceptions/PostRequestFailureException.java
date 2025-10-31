package uk.gov.di.authentication.oidc.exceptions;

import java.io.IOException;

public class PostRequestFailureException extends IOException {
    public PostRequestFailureException(String message) {
        super(message);
    }
}
