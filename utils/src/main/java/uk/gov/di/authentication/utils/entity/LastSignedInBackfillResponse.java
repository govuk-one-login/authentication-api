package uk.gov.di.authentication.utils.entity;

import com.google.gson.annotations.Expose;

public record LastSignedInBackfillResponse(
        @Expose long processedCount, @Expose long updatedCount, @Expose long skippedCount) {}
