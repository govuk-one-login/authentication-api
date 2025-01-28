package uk.gov.di.accountmanagement.entity;

public record DeletedAccountIdentifiers(
        String publicSubjectId, String legacySubjectId, String subjectId) {

    @Override
    public String toString() {
        return String.format(
                """
                Deleted Account Identifiers
                publicSubjectId: %s
                legacySubjectId: %s
                subjectId: %s
                """,
                publicSubjectId, legacySubjectId, subjectId);
    }
}
