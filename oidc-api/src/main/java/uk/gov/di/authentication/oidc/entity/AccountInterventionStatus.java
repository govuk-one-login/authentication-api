package uk.gov.di.authentication.oidc.entity;

public record AccountInterventionStatus(
        boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {}
