package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RemoveAccountResponse {

    @JsonProperty("subject_identifier")
    private String subjectID;

    @JsonProperty("legacy_sub")
    private String legacySubjectID;

    public RemoveAccountResponse(
            @JsonProperty(value = "subject_identifier") String subjectID,
            @JsonProperty(value = "legacy_sub") String legacySubjectID) {
        this.subjectID = subjectID;
        this.legacySubjectID = legacySubjectID;
    }

    public String getSubjectID() {
        return subjectID;
    }

    public String getLegacySubjectID() {
        return legacySubjectID;
    }
}
