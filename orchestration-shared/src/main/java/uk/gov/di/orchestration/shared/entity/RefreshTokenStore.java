package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class RefreshTokenStore {

    @Expose
    @SerializedName("refresh_token")
    private String refreshToken;

    @Expose
    @SerializedName("internal_pairwise_subject_id")
    private String internalPairwiseSubjectId = "missing";

    public RefreshTokenStore() {}

    public RefreshTokenStore(String refreshToken, String internalPairwiseSubjectId) {
        this.refreshToken = refreshToken;
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
    }

    public String getInternalPairwiseSubjectId() {
        return internalPairwiseSubjectId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
