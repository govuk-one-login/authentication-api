package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.GlobalLogoutMessage;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.GlobalLogoutAuditableEvent.GLOBAL_LOG_OUT_SUCCESS;

// QualityGateUnitTest
public class GlobalLogoutServiceTest {
    private static final String INTERNAL_COMMON_SUBJECT_ID = "test-icsid";
    public static final String SESSION_ID_1 = "test-session-id-1";
    public static final String SESSION_ID_2 = "test-session-id-2";
    public static final String CLIENT_SESSION_ID_1 = "test-client-session-1";
    public static final String CLIENT_SESSION_ID_2 = "test-client-session-2";
    public static final String CLIENT_ID = "test-client-id";
    public static final String PERSISTENT_SESSION_ID = "test-psid";
    public static final String IP_ADDRESS = "0.0.0.0";
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final BackChannelLogoutService backChannelLogoutService =
            mock(BackChannelLogoutService.class);
    private final AuditService auditService = mock(AuditService.class);
    private GlobalLogoutService globalLogoutService;

    @BeforeEach
    void setup() {
        globalLogoutService =
                new GlobalLogoutService(
                        orchSessionService,
                        orchClientSessionService,
                        dynamoClientService,
                        backChannelLogoutService,
                        auditService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotLogoutAnySessionsIfNoneFound() {
        withNoSessions();

        globalLogoutService.logoutAllSessions(
                globalLogoutMessage(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));

        verify(orchSessionService, never()).deleteSession(any());
        verify(orchClientSessionService, never()).deleteStoredClientSession(any());
        verifyNoInteractions(auditService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldLogoutOneSession() {
        withSessions(
                sessionWithClientSessions(SESSION_ID_1, CLIENT_SESSION_ID_1, CLIENT_SESSION_ID_2));

        globalLogoutService.logoutAllSessions(
                globalLogoutMessage(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));

        verify(orchSessionService).deleteSession(SESSION_ID_1);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_1);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_2);
        verify(auditService)
                .submitAuditEvent(
                        GLOBAL_LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));
    }

    // QualityGateRegressionTest
    @Test
    void shouldLogoutMultipleSessions() {
        withSessions(
                sessionWithClientSessions(SESSION_ID_1, CLIENT_SESSION_ID_1),
                sessionWithClientSessions(SESSION_ID_2, CLIENT_SESSION_ID_2));

        globalLogoutService.logoutAllSessions(
                globalLogoutMessage(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));

        verify(orchSessionService).deleteSession(SESSION_ID_1);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_1);
        verify(orchSessionService).deleteSession(SESSION_ID_2);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_2);
        verify(auditService)
                .submitAuditEvent(
                        GLOBAL_LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));
    }

    private void withNoSessions() {
        when(orchSessionService.getSessionsFromInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(List.of());
    }

    private void withSessions(OrchSessionItem... orchSessionItems) {
        when(orchSessionService.getSessionsFromInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(List.of(orchSessionItems));
    }

    private static OrchSessionItem sessionWithClientSessions(
            String sessionId, String... clientSessionIds) {
        var orchSessionItem = new OrchSessionItem(sessionId);
        List.of(clientSessionIds).forEach(orchSessionItem::addClientSession);
        return orchSessionItem;
    }

    private static GlobalLogoutMessage globalLogoutMessage(
            String icsid, String sessionId, String clientSessionId) {
        return new GlobalLogoutMessage(
                CLIENT_ID,
                "test-event-id",
                sessionId,
                clientSessionId,
                icsid,
                PERSISTENT_SESSION_ID,
                IP_ADDRESS);
    }

    private static TxmaAuditUser auditUser(String icsid, String sessionId, String clientSessionId) {
        return TxmaAuditUser.user()
                .withUserId(icsid)
                .withSessionId(sessionId)
                .withGovukSigninJourneyId(clientSessionId)
                .withPersistentSessionId(PERSISTENT_SESSION_ID)
                .withIpAddress(IP_ADDRESS);
    }
}
