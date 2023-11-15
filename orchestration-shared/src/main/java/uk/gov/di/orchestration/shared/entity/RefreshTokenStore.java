package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class RefreshTokenStore {

    @Expose
    @SerializedName("refresh_token")
    private String refreshToken;

    @Expose
    @SerializedName("internal_subject_id")
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
