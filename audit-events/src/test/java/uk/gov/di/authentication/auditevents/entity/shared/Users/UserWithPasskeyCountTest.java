package uk.gov.di.authentication.auditevents.entity.shared.Users;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserWithPasskeyCountTest {

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
        var passkeyCount = 5;

        var user = UserWithPasskeyCount.from(auditContext, passkeyCount);

        assertEquals(auditContext.email(), user.email());
        assertEquals(auditContext.clientSessionId(), user.govukSigninJourneyId());
        assertEquals(auditContext.ipAddress(), user.ipAddress());
        assertEquals(auditContext.persistentSessionId(), user.persistentSessionId());
        assertEquals(auditContext.sessionId(), user.sessionId());
        assertEquals(auditContext.subjectId(), user.userId());
        assertEquals(passkeyCount, user.passkeyCount());
    }
}
