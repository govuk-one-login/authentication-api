package uk.gov.di.authentication.auditevents.entity.shared.Users;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UserWithoutPhoneTest {

    @Test
    void createsAUserFromTheCorrectAuditContextFields() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withEmail("test@example.com")
                        .withSubjectId("internal-common-subject-id")
                        .withPersistentSessionId("persistent-session-id")
                        .withSessionId("session-id")
                        .withClientSessionId("signin-journey-id")
                        .withIpAddress("192.0.2.0/24");

        var user = UserWithoutPhone.fromAuditContext(auditContext);

        assertEquals(auditContext.email(), user.email());
        assertEquals(auditContext.clientSessionId(), user.govukSigninJourneyId());
        assertEquals(auditContext.ipAddress(), user.ipAddress());
        assertEquals(auditContext.persistentSessionId(), user.persistentSessionId());
        assertEquals(auditContext.sessionId(), user.sessionId());
        assertEquals(auditContext.subjectId(), user.userId());
        assertNull(user.publicSubjectId());
    }

    @Test
    void createsAUserWithPublicSubjectIdFromTheCorrectAuditContextFields() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withEmail("test@example.com")
                        .withSubjectId("internal-common-subject-id")
                        .withPersistentSessionId("persistent-session-id")
                        .withSessionId("session-id")
                        .withClientSessionId("signin-journey-id")
                        .withIpAddress("192.0.2.0/24");

        var user =
                UserWithoutPhone.fromAuditContext(
                        auditContext, "urn:fdc:gov.uk:2022:public-subject-id");

        assertEquals(auditContext.email(), user.email());
        assertEquals(auditContext.clientSessionId(), user.govukSigninJourneyId());
        assertEquals(auditContext.ipAddress(), user.ipAddress());
        assertEquals(auditContext.persistentSessionId(), user.persistentSessionId());
        assertEquals(auditContext.sessionId(), user.sessionId());
        assertEquals(auditContext.subjectId(), user.userId());
        assertEquals("urn:fdc:gov.uk:2022:public-subject-id", user.publicSubjectId());
    }
}
