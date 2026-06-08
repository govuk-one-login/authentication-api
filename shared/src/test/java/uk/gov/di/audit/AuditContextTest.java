package uk.gov.di.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

class AuditContextTest {
    @Test
    void shouldCreateNewInstanceForEachWithMethod() {
        // Given
        AuditContext original = AuditContext.emptyAuditContext();

        // When
        AuditContext withNewEmail = original.withEmail("new@example.com");
        AuditContext withNewPhone = original.withPhoneNumber("+447700900001");
        AuditContext withNewSubjectId = original.withSubjectId("new-subject-id");

        // Then
        assertNotSame(original, withNewEmail);
        assertNotSame(original, withNewPhone);
        assertNotSame(original, withNewSubjectId);
        assertEquals("new@example.com", withNewEmail.email());
        assertEquals("+447700900001", withNewPhone.phoneNumber());
        assertEquals("new-subject-id", withNewSubjectId.subjectId());
    }
}
