package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;

public record AccountInterventionResponse(
        @Expose AccountInterventionState state, @Expose String auditLevel) {}
