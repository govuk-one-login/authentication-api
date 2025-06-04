package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.text.ParseException;
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
    private final LogoutService logoutService = mock(LogoutService.class);
    private GlobalLogoutService globalLogoutService;

    @BeforeEach
    void setup() throws JOSEException, ParseException {
        globalLogoutService = new GlobalLogoutService(orchSessionService, logoutService);
    }

    @Test
    void shouldNotLogoutAnySessionsIfNoneFound() {
        withNoSessions();

        globalLogoutService.logoutAllSessions(INTERNAL_COMMON_SUBJECT_ID);

        verify(logoutService, never()).destroySessions(any());
    }

    @Test
    void shouldLogoutOneSession() {
        withSessions(
                sessionWithClientSessions(SESSION_ID_1, CLIENT_SESSION_ID_1, CLIENT_SESSION_ID_2));

        globalLogoutService.logoutAllSessions(INTERNAL_COMMON_SUBJECT_ID);

        verify(logoutService)
                .destroySessions(
                        new DestroySessionsRequest(
                                SESSION_ID_1, List.of(CLIENT_SESSION_ID_1, CLIENT_SESSION_ID_2)));
    }

    @Test
    void shouldLogoutMultipleSessions() {
        withSessions(
                sessionWithClientSessions(SESSION_ID_1, CLIENT_SESSION_ID_1),
                sessionWithClientSessions(SESSION_ID_2, CLIENT_SESSION_ID_2));

        globalLogoutService.logoutAllSessions(INTERNAL_COMMON_SUBJECT_ID);

        verify(logoutService)
                .destroySessions(
                        new DestroySessionsRequest(SESSION_ID_1, List.of(CLIENT_SESSION_ID_1)));
        verify(logoutService)
                .destroySessions(
                        new DestroySessionsRequest(SESSION_ID_2, List.of(CLIENT_SESSION_ID_2)));
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
}
