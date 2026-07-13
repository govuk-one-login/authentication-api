package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

public record InactiveAccountDataExportRequest(
        @Expose Integer parallelism, @Expose Integer totalSegments, @Expose Integer maxRetries) {}
