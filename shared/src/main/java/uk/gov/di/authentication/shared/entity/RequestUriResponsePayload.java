package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.oauth2.sdk.ErrorObject;

public class RequestUriResponsePayload {

    @JsonProperty(required = true)
    private boolean successfulRequest;

    @JsonProperty(required = true)
    private ErrorObject errorObject;

    public RequestUriResponsePayload(boolean successfulRequest, ErrorObject errorObject) {
        this.successfulRequest = successfulRequest;
        this.errorObject = errorObject;
    }

    public RequestUriResponsePayload() {}

    public boolean isSuccessfulRequest() {
        return successfulRequest;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
