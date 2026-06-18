package uk.gov.di.audit;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.UK_MOBILE_NUMBER;

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

    @Test
    void shouldPopulateAllFieldsFromUserContextAndRequest() {
        var authSession =
                new AuthSessionItem()
                        .withClientId(CLIENT_ID)
                        .withSessionId(SESSION_ID)
                        .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                        .withEmailAddress(EMAIL);

        var userContext =
                UserContext.builder(authSession)
                        .withClientSessionId(CLIENT_SESSION_ID)
                        .withTxmaAuditEvent(ENCODED_DEVICE_DETAILS)
                        .build();

        var request =
                new APIGatewayProxyRequestEvent()
                        .withHeaders(
                                Map.of(
                                        "X-Forwarded-For", IP_ADDRESS,
                                        "di-persistent-session-id", DI_PERSISTENT_SESSION_ID));

        var result = AuditContext.auditContextFrom(userContext, request, UK_MOBILE_NUMBER);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(CLIENT_SESSION_ID, result.clientSessionId());
        assertEquals(SESSION_ID, result.sessionId());
        assertEquals(INTERNAL_COMMON_SUBJECT_ID, result.subjectId());
        assertEquals(EMAIL, result.email());
        assertEquals(IP_ADDRESS, result.ipAddress());
        assertEquals(UK_MOBILE_NUMBER, result.phoneNumber());
        assertEquals(DI_PERSISTENT_SESSION_ID, result.persistentSessionId());
        assertEquals(ENCODED_DEVICE_DETAILS, result.txmaAuditEncoded());
    }
}
