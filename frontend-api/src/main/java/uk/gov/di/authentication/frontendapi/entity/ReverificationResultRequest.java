package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.validation.Required;

public class ReverificationResultRequest extends BaseFrontendRequest {

    @SerializedName("code")
    @Expose
    @Required
    private String code;

    public ReverificationResultRequest(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
