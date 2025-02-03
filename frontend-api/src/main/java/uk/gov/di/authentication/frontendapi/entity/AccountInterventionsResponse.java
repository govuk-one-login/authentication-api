package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;

import java.util.Objects;

public record AccountInterventionsResponse(
        @Expose boolean passwordResetRequired,
        @Expose boolean blocked,
        @Expose boolean temporarilySuspended,
        @Expose boolean reproveIdentity,
        @Expose Long appliedAt) {

    public AccountInterventionsResponse {
        Objects.requireNonNull(appliedAt);
    }
}
