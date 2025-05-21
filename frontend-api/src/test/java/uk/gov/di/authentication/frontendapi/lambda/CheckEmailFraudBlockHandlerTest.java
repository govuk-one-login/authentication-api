package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckEmailFraudBlockHandlerTest {

    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final String CLIENT_ID = "some-client-id";
    private static final String IP_ADDRESS = "123.123.123.123";
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    private static AuditService auditServiceMock;
    private static AuthenticationService authenticationServiceMock;
    private static Context contextMock;
    private static ConfigurationService configurationServiceMock;
    private static ClientService clientServiceMock;
    private static DynamoEmailCheckResultService dbMock;
    private static SessionService sessionServiceMock;
    private static ClientRegistry clientRegistry;
    private static UserContext userContext;
    private static AuthSessionService authSessionServiceMock;

    private final Session session = new Session();
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(SESSION_ID);
    private CheckEmailFraudBlockHandler handler;

    @BeforeAll
    static void init() {
        contextMock = mock(Context.class);
        dbMock = mock(DynamoEmailCheckResultService.class);
        clientServiceMock = mock(ClientService.class);
        auditServiceMock = mock(AuditService.class);
        configurationServiceMock = mock(ConfigurationService.class);
        authenticationServiceMock = mock(AuthenticationService.class);
        sessionServiceMock = mock(SessionService.class);
        clientRegistry = mock(ClientRegistry.class);
        userContext = mock(UserContext.class);
        authSessionServiceMock = mock(AuthSessionService.class);
    }

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getClientId()).thenReturn(CLIENT_ID);
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);
        when(configurationServiceMock.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationServiceMock.isEmailCheckEnabled()).thenReturn(true);
        when(authenticationServiceMock.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        when(authenticationServiceMock.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));

        handler =
                new CheckEmailFraudBlockHandler(
                        configurationServiceMock,
                        sessionServiceMock,
                        clientServiceMock,
                        authenticationServiceMock,
                        dbMock,
                        auditServiceMock,
                        authSessionServiceMock);
    }

    @ParameterizedTest
    @EnumSource(EmailCheckResultStatus.class)
    void shouldReturnCorrectStatusBasedOnDbResult(EmailCheckResultStatus status) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                getProxyRequestContext();

        var resultStore = new EmailCheckResultStore();
        resultStore.setStatus(status);
        when(dbMock.getEmailCheckStore(EMAIL)).thenReturn(Optional.of(resultStore));

        usingValidSession();

        var event =
                new APIGatewayProxyRequestEvent()
                        .withRequestContext(proxyRequestContext)
                        .withHeaders(VALID_HEADERS)
                        .withBody(format("{ \"email\": \"%s\" }", EMAIL));

        var expectedResponse = new CheckEmailFraudBlockResponse(EMAIL, status.getValue());
        var result =
                handler.handleRequestWithUserContext(
                        event, contextMock, new CheckEmailFraudBlockRequest(EMAIL), userContext);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(expectedResponse));
    }

    @Test
    void shouldSubmitAuditWithPendingStatusWhenEmailCheckResultStoreNotPresent() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                getProxyRequestContext();

        var resultStore = new EmailCheckResultStore();
        resultStore.setStatus(EmailCheckResultStatus.PENDING);
        when(dbMock.getEmailCheckStore(EMAIL)).thenReturn(Optional.of(resultStore));

        usingValidSession();

        long mockedTimestamp = 1719376320;
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(() -> NowHelper.toUnixTimestamp(NowHelper.now()))
                    .thenReturn(mockedTimestamp);

            var event =
                    new APIGatewayProxyRequestEvent()
                            .withHeaders(VALID_HEADERS)
                            .withRequestContext(proxyRequestContext)
                            .withBody(format("{ \"email\": \"%s\" }", EMAIL));

            var expectedResponse =
                    new CheckEmailFraudBlockResponse(
                            EMAIL, EmailCheckResultStatus.PENDING.getValue());
            var result =
                    handler.handleRequestWithUserContext(
                            event,
                            contextMock,
                            new CheckEmailFraudBlockRequest(EMAIL),
                            userContext);

            assertThat(result, hasStatus(200));
            assertThat(result, hasJsonBody(expectedResponse));

            verify(auditServiceMock)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_EMAIL_FRAUD_CHECK_BYPASSED,
                            new AuditContext(
                                    CLIENT_ID,
                                    CLIENT_SESSION_ID,
                                    SESSION_ID,
                                    AuditService.UNKNOWN,
                                    EMAIL,
                                    IP_ADDRESS,
                                    AuditService.UNKNOWN,
                                    DI_PERSISTENT_SESSION_ID,
                                    Optional.of(ENCODED_DEVICE_DETAILS)),
                            AuditService.MetadataPair.pair(
                                    "journey_type", JourneyType.REGISTRATION.getValue()),
                            AuditService.MetadataPair.pair(
                                    "assessment_checked_at_timestamp", mockedTimestamp),
                            AuditService.MetadataPair.pair("iss", "AUTH"));
        }
    }

    private void usingValidSession() {
        when(sessionServiceMock.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionServiceMock.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue());
    }

    private APIGatewayProxyRequestEvent.ProxyRequestContext getProxyRequestContext() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        proxyRequestContext.setIdentity(identityWithSourceIp(IP_ADDRESS));
        return proxyRequestContext;
    }
}
