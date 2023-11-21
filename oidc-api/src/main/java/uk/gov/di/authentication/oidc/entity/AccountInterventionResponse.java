package uk.gov.di.authentication.oidc.entity;

public record AccountInterventionResponse(AccountInterventionStatus state, String auditLevel) {}
