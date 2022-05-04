package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class LegacyRefreshTokenStore {

    @JsonProperty("refresh_tokens")
    private List<String> refreshTokens;

    @JsonProperty("internal_subject_id")
    private String internalSubjectId;

    public LegacyRefreshTokenStore() {}

    public LegacyRefreshTokenStore(List<String> refreshTokens, String internalSubjectId) {
        this.refreshTokens = refreshTokens;
        this.internalSubjectId = internalSubjectId;
    }

    public List<String> getRefreshTokens() {
        return refreshTokens;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }

    public LegacyRefreshTokenStore addRefreshToken(String refreshToken) {
        refreshTokens.add(refreshToken);
        return this;
    }

    public LegacyRefreshTokenStore removeRefreshToken(String refreshToken) {
        refreshTokens.remove(refreshToken);
        return this;
    }
}
