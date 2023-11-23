package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;

public class AccessTokenStore {

    @Expose private String token;

    @Expose private String internalSubjectId;

    @Expose private String internalPairwiseSubjectId = "missing";

    public AccessTokenStore() {}

    public AccessTokenStore(
            String token, String internalSubjectId, String internalPairwiseSubjectId) {
        this.token = token;
        this.internalSubjectId = internalSubjectId;
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
    }

    public String getToken() {
        return token;
    }

    public String getInternalSubjectId() {
        return internalSubjectId;
    }

    public String getInternalPairwiseSubjectId() {
        return internalPairwiseSubjectId;
    }
}
