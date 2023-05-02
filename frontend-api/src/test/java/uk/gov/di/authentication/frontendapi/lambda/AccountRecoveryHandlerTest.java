package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AccountRecoveryResponse;
import uk.gov.di.authentication.frontendapi.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountRecoveryHandlerTest {

    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final DynamoAccountModifiersService dynamoAccountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final ClientService clientService = mock(ClientService.class);
    private AccountRecoveryHandler handler;

    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));
        handler =
                new AccountRecoveryHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        dynamoAccountModifiersService);
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryWhenBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(true);
        usingValidSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var expectedResponse = new AccountRecoveryResponse(false);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(expectedResponse));
    }

    @Test
    void shouldBePermittedForAccountRecoveryWhenNoBlockIsPresentAndReturn200() {
        when(dynamoAccountModifiersService.isAccountRecoveryBlockPresent(anyString()))
                .thenReturn(false);
        usingValidSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var expectedResponse = new AccountRecoveryResponse(true);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(expectedResponse));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue());
    }
}
