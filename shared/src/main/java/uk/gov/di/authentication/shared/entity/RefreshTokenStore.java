package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RefreshTokenStore {

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("internal_subject_id")
    private String internalSubjectId;

    public RefreshTokenStore() {}

    public RefreshTokenStore(String refreshToken, String internalSubjectId) {
        this.refreshToken = refreshToken;
        this.internalSubjectId = internalSubjectId;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
