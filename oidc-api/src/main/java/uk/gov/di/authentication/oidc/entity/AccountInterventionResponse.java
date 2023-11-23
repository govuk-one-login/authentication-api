package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;

public record AccountInterventionResponse(
        @Expose AccountInterventionStatus state, @Expose String auditLevel) {}
