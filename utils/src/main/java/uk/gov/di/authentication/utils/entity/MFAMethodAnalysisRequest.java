package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

public record MFAMethodAnalysisRequest(
        @Expose Integer parallelism, @Expose Integer totalSegments) {}
