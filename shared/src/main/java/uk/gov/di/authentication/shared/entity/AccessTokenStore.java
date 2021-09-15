package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AccessTokenStore {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("internal_subject_id")
    private String internalSubjectId;

    public AccessTokenStore(
            @JsonProperty(required = true, value = "access_token") String accessToken,
            @JsonProperty(required = true, value = "internal_subject_id")
                    String internalSubjectId) {
        this.accessToken = accessToken;
        this.internalSubjectId = internalSubjectId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }
}
