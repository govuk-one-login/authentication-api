package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;

public class AccessTokenStore {

    @Expose private String token;
    @Expose private String internalPairwiseSubjectId = "missing";
    @Expose private String journeyId = "missing";

    public AccessTokenStore() {}

    public AccessTokenStore(String token, String internalPairwiseSubjectId, String journeyId) {
        this.token = token;
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
        this.journeyId = journeyId;
    }

    public String getToken() {
        return token;
    }

    public String getInternalPairwiseSubjectId() {
        return internalPairwiseSubjectId;
    }

    public String getJourneyId() {
        return journeyId;
    }
}
