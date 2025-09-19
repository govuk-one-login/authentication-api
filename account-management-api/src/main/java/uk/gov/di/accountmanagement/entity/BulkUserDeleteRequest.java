package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import uk.gov.di.authentication.shared.serialization.LocalDateTimeAdapter;

import java.time.LocalDateTime;
import java.util.List;

public record BulkUserDeleteRequest(
        @Expose String reference,
        @Expose List<String> emails,
        @Expose @JsonAdapter(LocalDateTimeAdapter.class) LocalDateTime createdAfter,
        @Expose @JsonAdapter(LocalDateTimeAdapter.class) LocalDateTime createdBefore) {}
