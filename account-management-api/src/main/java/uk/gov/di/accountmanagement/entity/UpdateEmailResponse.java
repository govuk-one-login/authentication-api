package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateEmailResponse {

    @JsonProperty("subject_identifier")
    private String subjectID;

    @JsonProperty("email_verified")
    private boolean emailVerified;

    @JsonProperty("legacy_sub")
    private String legacySubjectID;

    public UpdateEmailResponse(
            @JsonProperty(value = "subject_identifier") String subjectID,
            @JsonProperty(value = "email_verified") boolean emailVerified,
            @JsonProperty(value = "legacy_sub") String legacySubjectID) {
        this.subjectID = subjectID;
        this.emailVerified = emailVerified;
        this.legacySubjectID = legacySubjectID;
    }

    public String getSubjectID() {
        return subjectID;
    }

    public boolean getEmailVerified() {
        return emailVerified;
    }

    public String getLegacySubjectID() {
        return legacySubjectID;
    }
}
