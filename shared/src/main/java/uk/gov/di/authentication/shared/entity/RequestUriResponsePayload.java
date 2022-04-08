package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

public class RequestUriResponsePayload {

    @JsonProperty(required = true)
    private boolean successfulRequest;

    @JsonProperty private Map<String, List<String>> errorObject;

    public RequestUriResponsePayload(
            boolean successfulRequest, Map<String, List<String>> errorObject) {
        this.successfulRequest = successfulRequest;
        this.errorObject = errorObject;
    }

    public RequestUriResponsePayload(boolean successfulRequest) {
        this.successfulRequest = successfulRequest;
    }

    public RequestUriResponsePayload() {}

    public boolean isSuccessfulRequest() {
        return successfulRequest;
    }

    public Map<String, List<String>> getErrorObject() {
        return errorObject;
    }
}
