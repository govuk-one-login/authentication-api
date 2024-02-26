package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.validation.AuthAppCodeProcessor;
import uk.gov.di.authentication.frontendapi.validation.EmailCodeProcessor;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessorFactory;
import uk.gov.di.authentication.frontendapi.validation.PhoneNumberCodeProcessor;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class VerifyCodeHandlerEmailTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String SUBJECT_ID = "test-subject-id";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private static final String SECTOR_HOST = "test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String TEST_SUBJECT_ID = "test-subject-id";

    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(TEST_SUBJECT_ID, SECTOR_HOST, SALT);
    private final Session session =
            new Session("session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
    private final Json objectMapper = SerializationService.getInstance();
    public VerifyMfaCodeHandler handler;

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final MfaCodeProcessorFactory mfaCodeProcessorFactory =
            mock(MfaCodeProcessorFactory.class);
    private final AuthAppCodeProcessor authAppCodeProcessor = mock(AuthAppCodeProcessor.class);

    private final EmailCodeProcessor emailCodeProcessor = mock(EmailCodeProcessor.class);
    private final PhoneNumberCodeProcessor phoneNumberCodeProcessor =
            mock(PhoneNumberCodeProcessor.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @BeforeEach
    void setUp() {
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        when(clientRegistry.getClientName()).thenReturn(CLIENT_NAME);

        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest().toParameters());

        when(userProfile.getSubjectID()).thenReturn(SUBJECT_ID);
        when(configurationService.getBlockedEmailDuration()).thenReturn(900L);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));

        handler =
                new VerifyMfaCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        mfaCodeProcessorFactory,
                        cloudwatchMetricsService);
    }

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        CLIENT_ID,
                                        TEST_CLIENT_CODE,
                                        session.getSessionId(),
                                        CLIENT_SESSION_ID))));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                    "testclient.user1@digital.cabinet-office.gov.uk",
//                    "abc@digital.cabinet-office.gov.uk",
//                    "abc.def@digital.cabinet-office.gov.uk",
//                    "testclient.user2@internet.com",
            })
    void shouldReturn204ForValidVerifyEmailRequest(String email) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(emailCodeProcessor));

        session.setEmailAddress(email);
        session.setInternalCommonSubjectIdentifier(expectedCommonSubject);

        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.EMAIL, CODE, JourneyType.REGISTRATION);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(204));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(CodeRequest mfaCodeRequest)
            throws Json.JsonException {
        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        "Client-Session-Id",
                        CLIENT_SESSION_ID));
        event.setBody(objectMapper.writeValueAsString(mfaCodeRequest));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());
        return handler.handleRequest(event, context);
    }

    private AuthenticationRequest withAuthenticationRequest() {
        return new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope(OIDCScopeValue.OPENID),
                new ClientID(CLIENT_ID),
                URI.create("https://redirectUri"))
                .state(new State())
                .nonce(new Nonce())
                .build();
    }
}
