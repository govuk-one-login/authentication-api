package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;

public record BulkUserDeleteResponse(
        @Expose String message,
        @Expose String reference,
        @Expose long numberProcessed,
        @Expose long numberFailed,
        @Expose long numberNotFound,
        @Expose long numberFilteredOut) {}
