package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class RefreshTokenStore {

    @JsonProperty("refresh_tokens")
    private List<String> refreshTokens;

    @JsonProperty("internal_subject_id")
    private String internalSubjectId;

    public RefreshTokenStore(
            @JsonProperty(required = true, value = "refresh_tokens") List<String> refreshTokens,
            @JsonProperty(required = true, value = "internal_subject_id")
                    String internalSubjectId) {
        this.refreshTokens = refreshTokens;
        this.internalSubjectId = internalSubjectId;
    }

    public List<String> getRefreshTokens() {
        return refreshTokens;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }

    public RefreshTokenStore addRefreshToken(String refreshToken) {
        refreshTokens.add(refreshToken);
        return this;
    }

    public RefreshTokenStore removeRefreshToken(String refreshToken) {
        refreshTokens.remove(refreshToken);
        return this;
    }
}
