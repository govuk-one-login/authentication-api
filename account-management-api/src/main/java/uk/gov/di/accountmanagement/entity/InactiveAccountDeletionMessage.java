package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record InactiveAccountDeletionMessage(
        @Expose @SerializedName("publicSubjectId") String publicSubjectId) {}
