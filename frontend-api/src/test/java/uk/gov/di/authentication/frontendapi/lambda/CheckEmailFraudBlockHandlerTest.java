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
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckEmailFraudBlockHandlerTest {

    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String CLIENT_SESSION_ID = "known-client-session-id";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final String CLIENT_ID = "some-client-id";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    private static AuditService auditServiceMock;
    private static AuthenticationService authenticationServiceMock;
    private static Context contextMock;
    private static ConfigurationService configurationServiceMock;
    private static ClientService clientServiceMock;
    private static ClientSessionService clientSessionServiceMock;
    private static DynamoEmailCheckResultService dbMock;
    private static SessionService sessionServiceMock;

    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);
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
        clientSessionServiceMock = mock(ClientSessionService.class);
    }

    @BeforeEach
    void setup() {
        var userProfile = generateUserProfile();

        when(configurationServiceMock.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationServiceMock.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        when(authenticationServiceMock.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));

        handler =
                new CheckEmailFraudBlockHandler(
                        configurationServiceMock,
                        sessionServiceMock,
                        clientSessionServiceMock,
                        clientServiceMock,
                        authenticationServiceMock,
                        dbMock,
                        auditServiceMock);
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
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);

        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

        var expectedResponse = new CheckEmailFraudBlockResponse(EMAIL, status.getValue());
        var result = handler.handleRequest(event, contextMock);

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
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS);

        Date mockedDate = new Date();
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);

            var event = new APIGatewayProxyRequestEvent();
            event.setHeaders(headers);
            event.setRequestContext(proxyRequestContext);
            event.setBody(format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));

            var expectedResponse =
                    new CheckEmailFraudBlockResponse(
                            EMAIL, EmailCheckResultStatus.PENDING.getValue());
            var result = handler.handleRequest(event, contextMock);

            assertThat(result, hasStatus(200));
            assertThat(result, hasJsonBody(expectedResponse));

            verify(auditServiceMock)
                    .submitAuditEvent(
                            FrontendAuditableEvent.EMAIL_FRAUD_CHECK_BYPASSED,
                            CLIENT_ID,
                            CLIENT_SESSION_ID,
                            CLIENT_SESSION_ID,
                            AuditService.UNKNOWN,
                            EMAIL,
                            IP_ADDRESS,
                            AuditService.UNKNOWN,
                            PERSISTENT_ID,
                            new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                            AuditService.MetadataPair.pair(
                                    "journeyType", JourneyType.REGISTRATION.getValue()),
                            AuditService.MetadataPair.pair(
                                    "assessmentCheckedAtTimestamp", mockedDate),
                            AuditService.MetadataPair.pair("iss", "AUTH"));
        }
    }

    private void usingValidSession() {
        when(sessionServiceMock.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
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
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", expectedCommonSubject);
        authorizerParams.put("clientId", CLIENT_ID);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp(IP_ADDRESS));
        return proxyRequestContext;
    }
}
