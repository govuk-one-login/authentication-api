package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AccessTokenStore {

    @JsonProperty("token")
    private String token;

    @JsonProperty("internal_subject_id")
    private String internalSubjectId;

    public AccessTokenStore(
            @JsonProperty(required = true, value = "token") String token,
            @JsonProperty(required = true, value = "internal_subject_id")
                    String internalSubjectId) {
        this.token = token;
        this.internalSubjectId = internalSubjectId;
    }

    public String getToken() {
        return token;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }
}
