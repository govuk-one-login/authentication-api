package uk.gov.di.accountmanagement.entity;

public record DeletedAccountIdentifiers(
        String publicSubjectId, String legacySubjectId, String subjectId) {}
