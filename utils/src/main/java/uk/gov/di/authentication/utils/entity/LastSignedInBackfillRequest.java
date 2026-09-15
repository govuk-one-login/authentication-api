package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

import java.util.Map;

public record LastSignedInBackfillRequest(
        @Expose Map<Integer, Map<String, String>> segmentKeys,
        @Expose Long processedCount,
        @Expose Long updatedCount,
        @Expose Long skippedCount,
        @Expose Long invocationCount) {}
