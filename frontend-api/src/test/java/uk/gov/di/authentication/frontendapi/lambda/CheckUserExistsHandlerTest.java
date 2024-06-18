package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
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
import java.util.stream.Collectors;

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
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
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
    private static final Subject SUBJECT = new Subject();
    private static final String SECTOR_URI = "http://sector-identifier";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-id-value";
    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

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

    @Nested
    class WhenUserExists {
        @BeforeEach
        void setup() {
            usingValidSession();
            var userProfile =
                    generateUserProfile().withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER);
            setupUserProfileAndClient(Optional.of(userProfile));
        }

        @Test
        void shouldReturn200WithRelevantMfaMethod() throws Json.JsonException {
            MFAMethod mfaMethod1 = verifiedMfaMethod(MFAMethodType.AUTH_APP, false);
            MFAMethod mfaMethod2 = verifiedMfaMethod(MFAMethodType.SMS, true);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(
                            new UserCredentials().withMfaMethods(List.of(mfaMethod1, mfaMethod2)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);
            var phoneNumber = CommonTestVariables.UK_MOBILE_NUMBER;

            assertThat(result, hasStatus(200));
            var expectedResponse =
                    format(
                            """
                    {"email":%s,
                    "doesUserExist":true,
                    "mfaMethodType":"SMS",
                    "phoneNumberLastThree":"%s",
                    "lockoutInformation":[]}
                    """,
                            EMAIL_ADDRESS, phoneNumber.substring(phoneNumber.length() - 3));
            assertEquals(
                    JsonParser.parseString(result.getBody()),
                    JsonParser.parseString(expectedResponse));
        }

        @Test
        void shouldSubmitTheRelevantAuditEvent() {
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of()));
            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(200));
            var expectedRpPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), "sector-identifier", SALT.array());
            var expectedInternalPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), "test.account.gov.uk", SALT.array());
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL,
                            CLIENT_ID,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            expectedInternalPairwiseId,
                            EMAIL_ADDRESS,
                            IP_ADDRESS,
                            AuditService.UNKNOWN,
                            PERSISTENT_SESSION_ID,
                            new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                            AuditService.MetadataPair.pair("rpPairwiseId", expectedRpPairwiseId));
        }

        @Test
        void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of()));
            var req = userExistsRequest(EMAIL_ADDRESS);
            var headers =
                    req.getHeaders().entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            Map.Entry::getKey, Map.Entry::getValue));
            req.setHeaders(headers);

            var result = handler.handleRequest(req, context);

            assertThat(result, hasStatus(200));
            var expectedRpPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), "sector-identifier", SALT.array());
            var expectedInternalPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), "test.account.gov.uk", SALT.array());
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL,
                            CLIENT_ID,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            expectedInternalPairwiseId,
                            EMAIL_ADDRESS,
                            IP_ADDRESS,
                            AuditService.UNKNOWN,
                            PERSISTENT_SESSION_ID,
                            AuditService.RestrictedSection.empty,
                            AuditService.MetadataPair.pair("rpPairwiseId", expectedRpPairwiseId));
        }

        @Test
        void shouldReturn200WithLockInformationIfUserExistsAndMfaIsAuthApp() {
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
                                    "\"lockoutInformation\":["
                                            + "{\"lockType\":\"codeBlock\","
                                            + "\"mfaMethodType\":\"AUTH_APP\","
                                            + "\"lockTTL\":15,"
                                            + "\"journeyType\":\"SIGN_IN\"},"
                                            + "{\"lockType\":\"codeBlock\","
                                            + "\"mfaMethodType\":\"AUTH_APP\","
                                            + "\"lockTTL\":15,"
                                            + "\"journeyType\":\"PASSWORD_RESET_MFA\"}]"));
        }

        @Test
        void shouldReturnNoRedactedPhoneNumberIfNotPresent() throws Json.JsonException {
            setupUserProfileAndClient(Optional.of(generateUserProfile()));

            MFAMethod mfaMethod = verifiedMfaMethod(MFAMethodType.SMS, true);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL_ADDRESS))
                    .thenReturn(new UserCredentials().withMfaMethods(List.of(mfaMethod)));

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(200));
            var checkUserExistsResponse =
                    objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
            assertEquals(EMAIL_ADDRESS, checkUserExistsResponse.getEmail());
            assertNull(checkUserExistsResponse.getPhoneNumberLastThree());
        }

        @Test
        void shouldReturn400AndSaveEmailInUserSessionIfUserAccountIsLocked() {
            when(codeStorageService.getIncorrectPasswordCount(EMAIL_ADDRESS)).thenReturn(5);

            var result = handler.handleRequest(userExistsRequest(EMAIL_ADDRESS), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1045));
            verify(sessionService, times(1)).save(any());
            verify(auditService)
                    .submitAuditEvent(
                            ACCOUNT_TEMPORARILY_LOCKED,
                            CLIENT_ID,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            AuditService.UNKNOWN,
                            EMAIL_ADDRESS,
                            IP_ADDRESS,
                            AuditService.UNKNOWN,
                            PERSISTENT_SESSION_ID,
                            new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                            AuditService.MetadataPair.pair(
                                    "number_of_attempts_user_allowed_to_login", 5));
        }
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
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        EMAIL_ADDRESS,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)),
                        AuditService.MetadataPair.pair("rpPairwiseId", AuditService.UNKNOWN));
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
                        AuditService.UNKNOWN,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        "joe.bloggs",
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
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
                        Map.ofEntries(
                                Map.entry("Session-Id", session.getSessionId()),
                                Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                                Map.entry(
                                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                                        PERSISTENT_SESSION_ID),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS)))
                .withBody(format("{\"email\": \"%s\" }", email))
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
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
