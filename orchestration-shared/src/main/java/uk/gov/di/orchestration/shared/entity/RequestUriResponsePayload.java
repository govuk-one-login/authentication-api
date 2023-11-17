package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

import java.util.List;
import java.util.Map;

public class RequestUriResponsePayload {

    @Expose
    @Required
    @SerializedName("successfulRequest")
    private boolean successfulRequest;

    @Expose
    @SerializedName("errorObject")
    private Map<String, List<String>> errorObject;

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
