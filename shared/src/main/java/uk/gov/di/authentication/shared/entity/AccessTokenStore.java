package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;

public class AccessTokenStore {

    @Expose private String token;

    @Expose private String internalSubjectId;

    public AccessTokenStore() {}

    public AccessTokenStore(String token, String internalSubjectId) {
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
