package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public record MFARecord(
        @Expose @Required String mfaIdentifier,
        @Expose @Required String priorityIdentifier,
        @Expose @Required String mfaMethodType,
        @Expose @Required String endpoint,
        @Expose @Required boolean methodVerified) {}
