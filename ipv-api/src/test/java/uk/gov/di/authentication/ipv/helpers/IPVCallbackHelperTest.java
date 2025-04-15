package uk.gov.di.authentication.ipv.helpers;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IpvCallbackException;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_NAME;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class IPVCallbackHelperTest {
    private final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private final AuditContext auditContext = mock(AuditContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthCodeResponseGenerationService authCodeResponseService =
            mock(AuthCodeResponseGenerationService.class);
    private static final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final OidcAPI oidcAPI = mock(OidcAPI.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);

    private static final URI OIDC_TRUSTMARK_URI = URI.create("https://base-url.com/trustmark");
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_PHONE_NUMBER = "012345678902";
    private static final Subject PUBLIC_SUBJECT =
            new Subject("TsEVC7vg0NPAmzB33vRUFztL2c0-fecKWKcc73fuDhc");
    private static final Subject SUBJECT = new Subject("subject-id");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID_WITH_INTERVENTION =
            "internal-common-subject-id-with-intervention";
    private static final byte[] salt =
            "Mmc48imEuO5kkVW7NtXVtx5h0mbCTfXsqXdWvbRMzdw=".getBytes(StandardCharsets.UTF_8);
    private static final String BASE_64_ENCODED_SALT = Base64.getEncoder().encodeToString(salt);
    private static final List<VectorOfTrust> VTR_LIST_P1_AND_P2 =
            List.of(
                    VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.NONE),
                    VectorOfTrust.of(
                            CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));
    private static final List<VectorOfTrust> VTR_LIST_P2_ONLY =
            List.of(
                    VectorOfTrust.of(
                            CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                    VectorOfTrust.of(
                            CredentialTrustLevel.MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL));
    private static final Subject RP_PAIRWISE_SUBJECT = new Subject("rp-pairwise-id");
    private static final State RP_STATE = new State();
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final Long AUTH_TIME = 1234L;
    private static final UserProfile userProfile = generateUserProfile();
    private static final UserInfo authUserInfo = generateAuthUserInfo();

    private static final UserInfo p0VotUserIdentityUserInfo =
            new UserInfo(
                    new JSONObject(
                            Map.of(
                                    "sub", "sub-val",
                                    "vot", "P0",
                                    "vtm", OIDC_TRUSTMARK_URI.toString())));
    private static final UserInfo p2VotUserIdentityUserInfo =
            new UserInfo(
                    new JSONObject(
                            Map.of(
                                    "sub", "sub-val",
                                    "vot", "P2",
                                    "vtm", OIDC_TRUSTMARK_URI.toString(),
                                    "https://vocab.account.gov.uk/v1/coreIdentity", "core-identity",
                                    "https://vocab.account.gov.uk/v1/passport", "passport")));

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(IPVCallbackHelper.class);

    private IPVCallbackHelper helper;

    private static Stream<Arguments> validUserIdentities() {
        return Stream.of(
                Arguments.of(p0VotUserIdentityUserInfo, VTR_LIST_P1_AND_P2),
                Arguments.of(p2VotUserIdentityUserInfo, VTR_LIST_P2_ONLY));
    }

    @BeforeEach
    void setUp() {
        clearInvocations(orchAuthCodeService);

        helper =
                new IPVCallbackHelper(
                        auditService,
                        authCodeResponseService,
                        orchAuthCodeService,
                        cloudwatchMetricsService,
                        dynamoClientService,
                        dynamoIdentityService,
                        dynamoService,
                        SerializationService.getInstance(),
                        sessionService,
                        sqsClient,
                        oidcAPI,
                        orchSessionService);
        when(accountInterventionService.getAccountIntervention(
                        TEST_INTERNAL_COMMON_SUBJECT_ID, auditContext))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, false, false, false)));
        when(accountInterventionService.getAccountIntervention(
                        TEST_INTERNAL_COMMON_SUBJECT_ID_WITH_INTERVENTION, auditContext))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, true, false, false)));

        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        anyLong()))
                .thenReturn(AUTH_CODE);

        when(oidcAPI.trustmarkURI()).thenReturn(OIDC_TRUSTMARK_URI);
    }

    @Test
    void shouldReturnAuthenticationErrorResponse() {
        var authRequest = generateAuthRequest(new OIDCClaimsRequest());
        var errorObject = new ErrorObject("error_object", "Error object description");

        var response =
                helper.generateAuthenticationErrorResponse(
                        authRequest, errorObject, false, CLIENT_SESSION_ID, SESSION_ID);
        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()), errorObject, RP_STATE, null)
                        .toURI()
                        .toString();

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Error in IPV AuthorisationResponse. ErrorCode: error_object. ErrorDescription: Error object description. No Session Error: false")));
        verify(auditService)
                .submitAuditEvent(
                        IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
                        authRequest.getClientID().getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withSessionId(SESSION_ID));
        assertEquals(302, response.getStatusCode());
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @ParameterizedTest
    @MethodSource("validUserIdentities")
    void shouldReturnEmptyErrorObjectIfUserIdentityVotInVtrList(
            UserInfo userInfo, List<VectorOfTrust> vtrList) throws IpvCallbackException {
        var response = helper.validateUserIdentityResponse(userInfo, vtrList);

        assertEquals(Optional.empty(), response);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldReturnAccessDeniedIfIPVMissingVot() throws IpvCallbackException {
        var missingVotUserIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of("sub", "sub-val", "vtm", OIDC_TRUSTMARK_URI.toString())));

        var response =
                helper.validateUserIdentityResponse(
                        missingVotUserIdentityUserInfo, VTR_LIST_P2_ONLY);

        assertEquals(Optional.of(OAuth2Error.ACCESS_DENIED), response);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldReturnAccessDeniedIfIpvVotNotInVtrList() throws IpvCallbackException {
        var response =
                helper.validateUserIdentityResponse(p0VotUserIdentityUserInfo, VTR_LIST_P2_ONLY);

        assertEquals(Optional.of(OAuth2Error.ACCESS_DENIED), response);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldThrowIpvCallbackExceptionIfTrustmarkIsInvalid() {
        var invalidTrustmarkUserIdentityUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P2",
                                        "vtm", "invalidBaseUrl" + "/trustmark")));

        var exception =
                assertThrows(
                        IpvCallbackException.class,
                        () ->
                                helper.validateUserIdentityResponse(
                                        invalidTrustmarkUserIdentityUserInfo, VTR_LIST_P2_ONLY),
                        "Expected to throw IpvCallbackException");

        assertEquals("IPV trustmark is invalid", exception.getMessage());

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldQueueSPOTRequestIfValidFormat() throws JsonException {
        helper.queueSPOTRequest(
                new LogIds(),
                "sector-identifier",
                userProfile,
                SUBJECT,
                p2VotUserIdentityUserInfo,
                CLIENT_ID.getValue());

        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Constructing SPOT request ready to queue")));
        var spotRequestString =
                "{\"in_claims\":{\"https://vocab.account.gov.uk/v1/coreIdentity\":\"core-identity\",\"https://vocab.account.gov.uk/v1/credentialJWT\":null,\"vot\":\"P2\",\"vtm\":\"https://base-url.com/trustmark\"},\"in_local_account_id\":\"subject-id\",\"in_salt\":null,\"in_rp_sector_id\":\"sector-identifier\",\"out_sub\":\"subject-id\",\"log_ids\":{\"session_id\":null,\"persistent_session_id\":null,\"request_id\":null,\"client_id\":null,\"client_session_id\":null},\"out_audience\":\""
                        + CLIENT_ID.getValue()
                        + "\"}";
        verify(sqsClient).send(spotRequestString);
        assertThat(
                logging.events(), hasItem(withMessageContaining("SPOT request placed on queue")));
    }

    @Test
    void shouldThrowJsonExceptionAndDoesNotInteractWithSqsIfCannotMapRequestToJson() {
        var objectMapper = mock(SerializationService.class);
        helper =
                new IPVCallbackHelper(
                        auditService,
                        authCodeResponseService,
                        orchAuthCodeService,
                        cloudwatchMetricsService,
                        dynamoClientService,
                        dynamoIdentityService,
                        dynamoService,
                        objectMapper,
                        sessionService,
                        sqsClient,
                        oidcAPI,
                        orchSessionService);
        when(objectMapper.writeValueAsString(any())).thenThrow(new JsonException("json-exception"));

        var exception =
                assertThrows(
                        JsonException.class,
                        () ->
                                helper.queueSPOTRequest(
                                        new LogIds(),
                                        "sector-identifier",
                                        userProfile,
                                        SUBJECT,
                                        p2VotUserIdentityUserInfo,
                                        CLIENT_ID.getValue()),
                        "Expected to throw JsonException");

        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Constructing SPOT request ready to queue")));
        verifyNoInteractions(sqsClient);
        assertEquals("json-exception", exception.getMessage());

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldSaveAdditionalIdentityClaimsToDynamo() {
        helper.saveIdentityClaimsToDynamo(
                CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, p2VotUserIdentityUserInfo);

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Checking for additional identity claims to save to dynamo")));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Additional identity claims present: true")));
        verify(dynamoIdentityService)
                .saveIdentityClaims(
                        CLIENT_SESSION_ID,
                        "rp-pairwise-id",
                        Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                        "P2",
                        "core-identity");
    }

    @Test
    void handlesMissingCoreIdentity() {
        var userInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub", "sub-val",
                                        "vot", "P2",
                                        "vtm", OIDC_TRUSTMARK_URI.toString(),
                                        "https://vocab.account.gov.uk/v1/passport", "passport")));
        helper.saveIdentityClaimsToDynamo(CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo);

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Checking for additional identity claims to save to dynamo")));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Additional identity claims present: true")));
        verify(dynamoIdentityService)
                .saveIdentityClaims(
                        CLIENT_SESSION_ID,
                        "rp-pairwise-id",
                        Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                        "P2",
                        "");
    }

    @Test
    void handlesNullCoreIdentity() {
        var userInfo =
                new UserInfo(
                        new JSONObject(
                                new HashMap<String, String>() {
                                    {
                                        put("sub", "sub-val");
                                        put("vot", "P2");
                                        put("vtm", OIDC_TRUSTMARK_URI.toString());
                                        put("https://vocab.account.gov.uk/v1/coreIdentity", null);
                                        put("https://vocab.account.gov.uk/v1/passport", "passport");
                                    }
                                }));
        helper.saveIdentityClaimsToDynamo(CLIENT_SESSION_ID, RP_PAIRWISE_SUBJECT, userInfo);

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Checking for additional identity claims to save to dynamo")));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Additional identity claims present: true")));
        verify(dynamoIdentityService)
                .saveIdentityClaims(
                        CLIENT_SESSION_ID,
                        "rp-pairwise-id",
                        Map.of("https://vocab.account.gov.uk/v1/passport", "passport"),
                        "P2",
                        "");
    }

    @Test
    void shouldGenerateAndSaveAuthorisationCode() throws UserNotFoundException {
        OrchSessionItem orchSession = new OrchSessionItem(SESSION_ID).withAuthTime(AUTH_TIME);

        helper.generateReturnCodeAuthenticationResponse(
                generateAuthRequest(new OIDCClaimsRequest()),
                CLIENT_SESSION_ID,
                userProfile,
                new Session(),
                SESSION_ID,
                orchSession,
                CLIENT_NAME,
                RP_PAIRWISE_SUBJECT,
                "an-internal-pairwise-subject-id",
                new UserInfo(new Subject()),
                "127.0.0.1",
                "a-persistent-session-id",
                CLIENT_ID.getValue());

        assertAuthorisationCodeGeneratedAndSaved();
    }

    private static UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumber(TEST_PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .withSubjectID(SUBJECT.getValue());
    }

    private static UserInfo generateAuthUserInfo() {
        return new UserInfo(
                new JSONObject(
                        Map.of(
                                "sub",
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                "client_session_id",
                                CLIENT_SESSION_ID,
                                "email",
                                TEST_EMAIL_ADDRESS,
                                "phone_number",
                                TEST_PHONE_NUMBER,
                                "salt",
                                BASE_64_ENCODED_SALT,
                                "local_account_id",
                                SUBJECT.getValue())));
    }

    public static AuthenticationRequest generateAuthRequest(OIDCClaimsRequest oidcClaimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(nonce)
                .claims(oidcClaimsRequest)
                .build();
    }

    private void assertAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(1))
                .generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        eq(AUTH_TIME));
    }

    private void assertNoAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(0))
                .generateAndSaveAuthorisationCode(any(), any(), any(), any());
    }
}
