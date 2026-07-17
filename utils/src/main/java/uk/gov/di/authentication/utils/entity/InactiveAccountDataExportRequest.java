package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

import java.util.Map;

public record InactiveAccountDataExportRequest(
        @Expose Map<Integer, Map<String, String>> segmentKeys,
        @Expose Long processedCount,
        @Expose Long writtenCount) {}
