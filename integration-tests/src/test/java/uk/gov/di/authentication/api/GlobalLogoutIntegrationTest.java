package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.oidc.lambda.GlobalLogoutHandler;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.basetest.IntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.testsupport.helpers.SqsIntegrationTestHelper.createSqsEvent;

public class GlobalLogoutIntegrationTest extends IntegrationTest {
    @RegisterExtension
    public static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    public static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    private static final String SESSION_ID = "session-id";
    private static final String SESSION_ID_1 = "session-id-1";
    private static final String SESSION_ID_2 = "session-id-2";
    private static final String SESSION_ID_3 = "session-id-3";
    private static final String INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String CLIENT_SESSION_ID_1 = "client-session-id-1";
    private static final String CLIENT_SESSION_ID_2 = "client-session-id-2";
    private static final String CLIENT_SESSION_ID_3 = "client-session-id-3";
    private static final SerializationService OBJECT_MAPPER = SerializationService.getInstance();
    private GlobalLogoutHandler handler;

    @BeforeEach
    void setup() {
        handler = new GlobalLogoutHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldGenerateNoErrorsIfNoSessionsFoundForIcsid() {
        var inputMessage =
                createGlobalLogoutMessage(
                        INTERNAL_COMMON_SUBJECT_ID, SESSION_ID, CLIENT_SESSION_ID);

        var response = handler.handleRequest(createSqsEvent(inputMessage), mock(Context.class));

        assertThat(response, equalTo(noBatchItemFailures()));
    }

    @Test
    void shouldLogoutAllSessionsForIcsid() {
        withSessions(
                sessionWithClientSessions("same-icsid", SESSION_ID_1, CLIENT_SESSION_ID_1),
                sessionWithClientSessions("same-icsid", SESSION_ID_2, CLIENT_SESSION_ID_2),
                sessionWithClientSessions("different-icsid", SESSION_ID_3, CLIENT_SESSION_ID_3));
        var inputMessage =
                createGlobalLogoutMessage("same-icsid", SESSION_ID_1, CLIENT_SESSION_ID_2);

        var response = handler.handleRequest(createSqsEvent(inputMessage), mock(Context.class));

        assertThat(response, equalTo(noBatchItemFailures()));

        assertFalse(sessionsExist(SESSION_ID_1, SESSION_ID_2));
        assertFalse(clientSessionsExist(CLIENT_SESSION_ID_1, CLIENT_SESSION_ID_2));

        assertTrue(sessionsExist(SESSION_ID_3));
        assertTrue(clientSessionsExist(CLIENT_SESSION_ID_3));
    }

    private static String createGlobalLogoutMessage(
            String internalCommonSubjectId, String sessionId, String clientSessionId) {
        return OBJECT_MAPPER.writeValueAsString(
                Map.of(
                        "internal_common_subject_id", internalCommonSubjectId,
                        "session_id", sessionId,
                        "client_session_id", clientSessionId));
    }

    private void withSessions(OrchSessionItem... orchSessionItems) {
        Stream.of(orchSessionItems).forEach(orchSessionExtension::addSession);
    }

    private OrchSessionItem sessionWithClientSessions(
            String internalCommonSubjectId, String sessionId, String... clientSessionIds) {
        var orchSessionItem =
                new OrchSessionItem(sessionId).withInternalCommonSubjectId(internalCommonSubjectId);
        List.of(clientSessionIds)
                .forEach(
                        clientSessionId -> {
                            var clientSession =
                                    new OrchClientSessionItem(clientSessionId)
                                            .withAuthRequestParams(
                                                    generateAuthRequest().toParameters());
                            orchClientSessionExtension.storeClientSession(clientSession);
                            orchSessionItem.addClientSession(clientSessionId);
                        });
        return orchSessionItem;
    }

    private AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        responseType,
                        scope,
                        new ClientID("test-client"),
                        URI.create("http://localhost:8080/redirect"))
                .state(state)
                .nonce(new Nonce())
                .build();
    }

    private SQSBatchResponse noBatchItemFailures() {
        return new SQSBatchResponse(List.of());
    }

    private boolean sessionsExist(String... sessionIds) {
        return Stream.of(sessionIds)
                .allMatch(sessionId -> orchSessionExtension.getSession(sessionId).isPresent());
    }

    private boolean clientSessionsExist(String... clientSessionIds) {
        return Stream.of(clientSessionIds)
                .allMatch(
                        clientSessionId ->
                                orchClientSessionExtension
                                        .getClientSession(clientSessionId)
                                        .isPresent());
    }
}
