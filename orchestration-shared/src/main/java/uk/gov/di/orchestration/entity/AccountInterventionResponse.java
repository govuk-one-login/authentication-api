package uk.gov.di.orchestration.entity;

import com.google.gson.annotations.Expose;

public record AccountInterventionResponse(
        @Expose AccountInterventionStatus state, @Expose String auditLevel) {}
