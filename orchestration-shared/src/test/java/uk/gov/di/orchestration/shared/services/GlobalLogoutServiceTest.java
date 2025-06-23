package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.GlobalLogoutMessage;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GlobalLogoutServiceTest {
    private static final String INTERNAL_COMMON_SUBJECT_ID = "test-icsid";
    public static final String SESSION_ID_1 = "test-session-id-1";
    public static final String SESSION_ID_2 = "test-session-id-2";
    public static final String CLIENT_SESSION_ID_1 = "test-client-session-1";
    public static final String CLIENT_SESSION_ID_2 = "test-client-session-2";
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final BackChannelLogoutService backChannelLogoutService =
            mock(BackChannelLogoutService.class);
    private GlobalLogoutService globalLogoutService;

    @BeforeEach
    void setup() {
        globalLogoutService =
                new GlobalLogoutService(
                        orchSessionService,
                        orchClientSessionService,
                        dynamoClientService,
                        backChannelLogoutService);
    }

    @Test
    void shouldNotLogoutAnySessionsIfNoneFound() {
        withNoSessions();

        globalLogoutService.logoutAllSessions(
                globalLogoutMessage(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));

        verify(orchSessionService, never()).deleteSession(any());
        verify(orchClientSessionService, never()).deleteStoredClientSession(any());
    }

    @Test
    void shouldLogoutOneSession() {
        withSessions(
                sessionWithClientSessions(SESSION_ID_1, CLIENT_SESSION_ID_1, CLIENT_SESSION_ID_2));

        globalLogoutService.logoutAllSessions(
                globalLogoutMessage(INTERNAL_COMMON_SUBJECT_ID, SESSION_ID_1, CLIENT_SESSION_ID_1));

        verify(orchSessionService).deleteSession(SESSION_ID_1);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_1);
        verify(orchClientSessionService).deleteStoredClientSession(CLIENT_SESSION_ID_2);
    }

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
    }

    private void withNoSessions() {
        when(orchSessionService.getSessionsFromInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(List.of());
    }

    private void withSessions(OrchSessionItem... orchSessionItems) {
        when(orchSessionService.getSessionsFromInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(List.of(orchSessionItems));
    }

    private OrchSessionItem sessionWithClientSessions(
            String sessionId, String... clientSessionIds) {
        var orchSessionItem = new OrchSessionItem(sessionId);
        List.of(clientSessionIds).forEach(orchSessionItem::addClientSession);
        return orchSessionItem;
    }

    private static GlobalLogoutMessage globalLogoutMessage(
            String icsid, String sessionId, String clientSessionId) {
        return new GlobalLogoutMessage(
                "test-client-id",
                "test-event-id",
                sessionId,
                clientSessionId,
                icsid,
                "test-psid",
                "0.0.0.0");
    }
}
