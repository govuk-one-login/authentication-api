package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record LegacyAccountDeletionMessage(
        @Expose @SerializedName("public_subject_id") String publicSubjectId,
        @Expose @SerializedName("legacy_subject_id") String legacySubjectId,
        @Expose @SerializedName("user_id") String commonSubjectId) {}
