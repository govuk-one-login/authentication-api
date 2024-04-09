package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckUserExistsHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private CheckUserExistsHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private final Session session = new Session(IdGenerator.generate());
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final String PHONE_NUMBER = "+44987654321";
    private static final Subject SUBJECT = new Subject();
    private static final String SECTOR_URI = "http://sector-identifier";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-id-value";
    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CheckUserExistsHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    void setup() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getMaxPasswordRetries()).thenReturn(5);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL_ADDRESS)).thenReturn(0);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");

        handler =
                new CheckUserExistsHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        codeStorageService);
        reset(authenticationService);
    }

    @Test
    void shouldReturn200WithLockInformationIfUserExistsAndMfaIsAuthApp() {
        usingValidSession();
        var userProfile = generateUserProfile().withAccountVerified(1);
        setupUserProfileAndClient(Optional.of(userProfile));
        when(codeStorageService.getMfaCodeBlockTimeToLive(
                        EMAIL_ADDRESS, MFAMethodType.AUTH_APP, JourneyType.SIGN_IN))
                .thenReturn(15L);
        when(codeStorageService.getMfaCodeBlockTimeToLive(
                        EMAIL_ADDRESS, MFAMethodType.AUTH_APP, JourneyType.PASSWORD_RESET_MFA))
                .thenReturn(15L);
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(
                        EMAIL_ADDRESS, MFAMethodType.AUTH_APP))
                .thenReturn(6);
        MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod1)));
        var event = userExistsRequest(EMAIL_ADDRESS);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(200));
        assertTrue(
                result.getBody()
                        .contains(
                                "\"lockType\":\"codeBlock\","
                                        + "\"mfaMethodType\":\"AUTH_APP\","
                                        + "\"lockTTL\":15,"
                                        + "\"journeyType\":\"SIGN_IN\""));

        assertTrue(
                result.getBody()
                        .contains(
                                "\"lockType\":\"codeBlock\","
                                        + "\"mfaMethodType\":\"AUTH_APP\","
                                        + "\"lockTTL\":15,"
                                        + "\"journeyType\":\"PASSWORD_RESET_MFA\""));
    }

    @Test
    void shouldReturn200IfUserExists() throws Json.JsonException {
        usingValidSession();
        var userProfile = generateUserProfile().withPhoneNumber(PHONE_NUMBER);
        setupUserProfileAndClient(Optional.of(userProfile));

        MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, false);
        MFAMethod mfaMethod2 = verifiedMfaMethod(MFAMethodType.SMS, true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod1, mfaMethod2)));

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(200));
        var checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(EMAIL_ADDRESS, checkUserExistsResponse.getEmail());
        assertEquals("321", checkUserExistsResponse.getPhoneNumberLastThree());
        assertEquals(MFAMethodType.SMS, checkUserExistsResponse.getMfaMethodType());
        assertTrue(checkUserExistsResponse.doesUserExist());
        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "sector-identifier", SALT.array());
        var expectedInternalPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "test.account.gov.uk", SALT.array());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedInternalPairwiseId,
                        EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        AuditService.MetadataPair.pair("rpPairwiseId", expectedRpPairwiseId));
    }

    @Test
    void shouldReturn200IfUserDoesNotExist() throws Json.JsonException {
        usingValidSession();

        setupUserProfileAndClient(Optional.empty());

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(200));
        var checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.getEmail(), equalTo(EMAIL_ADDRESS));
        assertFalse(checkUserExistsResponse.doesUserExist());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_NO_ACCOUNT_WITH_EMAIL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        AuditService.UNKNOWN,
                        EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        AuditService.MetadataPair.pair("rpPairwiseId", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturnNoRedactedPhoneNumberIfNotPresent() throws Json.JsonException {
        usingValidSession();
        setupUserProfileAndClient(Optional.of(generateUserProfile()));

        MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, false);
        MFAMethod mfaMethod2 = verifiedMfaMethod(MFAMethodType.SMS, true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod1, mfaMethod2)));

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(200));
        var checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(EMAIL_ADDRESS, checkUserExistsResponse.getEmail());
        assertNull(checkUserExistsResponse.getPhoneNumberLastThree());
        assertEquals(MFAMethodType.SMS, checkUserExistsResponse.getMfaMethodType());
        assertTrue(checkUserExistsResponse.doesUserExist());
        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "sector-identifier", SALT.array());
        var expectedInternalPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "test.account.gov.uk", SALT.array());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedInternalPairwiseId,
                        EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        AuditService.MetadataPair.pair("rpPairwiseId", expectedRpPairwiseId));
    }

    @Test
    void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();

        var event =
                new APIGatewayProxyRequestEvent()
                        .withHeaders(singletonMap("Session-Id", session.getSessionId()))
                        .withBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfRequestIsMissingSessionId() {
        var event = new APIGatewayProxyRequestEvent().withBody("{ }");

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfEmailAddressIsInvalid() {
        usingValidSession();

        var result = handler.handleRequest(userExistsRequest("joe.bloggs"), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_INVALID_EMAIL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "joe.bloggs",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    @Test
    void shouldReturn400AndSaveEmailInUserSessionIfUserAccountIsLocked() {
        usingValidSession();
        setupUserProfileAndClient(Optional.of(generateUserProfile()));

        when(codeStorageService.getIncorrectPasswordCount(EMAIL_ADDRESS)).thenReturn(5);

        var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1045));
        verify(sessionService, times(1)).save(any());
        verify(auditService)
                .submitAuditEvent(
                        ACCOUNT_TEMPORARILY_LOCKED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        AuditService.UNKNOWN,
                        EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(SUBJECT.getValue())
                .withTermsAndConditions(
                        new TermsAndConditions("1.0", NowHelper.now().toInstant().toString()));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withRedirectUrls(singletonList("http://localhost/oidc/redirect"))
                .withClientID(CLIENT_ID)
                .withContacts(singletonList(EMAIL_ADDRESS))
                .withPublicKey(null)
                .withSectorIdentifierUri(SECTOR_URI)
                .withScopes(singletonList("openid"))
                .withCookieConsentShared(true)
                .withSubjectType("pairwise");
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();

        return new ClientSession(
                authRequest.toParameters(), null, mock(VectorOfTrust.class), CLIENT_NAME);
    }

    private void setupUserProfileAndClient(Optional<UserProfile> maybeUserProfile) {
        maybeUserProfile.ifPresent(
                profile ->
                        when(authenticationService.getOrGenerateSalt(profile))
                                .thenReturn(SALT.array()));
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_ADDRESS))
                .thenReturn(maybeUserProfile);
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(generateClientRegistry()));
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(getClientSession()));
    }

    private APIGatewayProxyRequestEvent userExistsRequest(String email) {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(
                        Map.of(
                                "Session-Id",
                                session.getSessionId(),
                                CLIENT_SESSION_ID_HEADER,
                                CLIENT_SESSION_ID,
                                PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                                PERSISTENT_SESSION_ID))
                .withBody(format("{\"email\": \"%s\" }", email))
                .withRequestContext(contextWithSourceIp("123.123.123.123"));
    }


    private MFAMethod verifiedMfaMethod(MFAMethodType mfaMethodType, Boolean enabled) {
        return new MFAMethod(
                mfaMethodType.getValue(),
                "some-credential-value",
                true,
                enabled,
                NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
    }
}
