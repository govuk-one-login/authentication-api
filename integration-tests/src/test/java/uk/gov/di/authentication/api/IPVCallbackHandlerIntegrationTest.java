package uk.gov.di.authentication.api;

import com.google.gson.internal.LinkedTreeMap;
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
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.testsupport.helpers.SpotQueueAssertionHelper;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.AuthenticationCallbackUserInfoStoreExtension;
import uk.gov.di.orchestration.sharedtest.extensions.CrossBrowserStorageExtension;
import uk.gov.di.orchestration.sharedtest.extensions.IPVStubExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.orchestration.sharedtest.extensions.StateStorageExtension;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SPOT_REQUESTED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST;
import static uk.gov.di.authentication.testsupport.helpers.OrchAuthCodeAssertionHelper.assertOrchAuthCodeSaved;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.calculatePairwiseIdentifier;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;

    @RegisterExtension public static final IPVStubExtension ipvStub = new IPVStubExtension();

    @RegisterExtension
    public static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    @RegisterExtension
    public static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @RegisterExtension
    protected static final AuthenticationCallbackUserInfoStoreExtension userInfoStorageExtension =
            new AuthenticationCallbackUserInfoStoreExtension(180);

    @RegisterExtension
    public static final OrchAuthCodeExtension orchAuthCodeExtension = new OrchAuthCodeExtension();

    @RegisterExtension
    public static final StateStorageExtension stateStorageExtension = new StateStorageExtension();

    @RegisterExtension
    public static final CrossBrowserStorageExtension crossBrowserStorageExtension =
            new CrossBrowserStorageExtension();

    protected static ConfigurationService configurationService;

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_NAME = "test-client-name";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final State RP_STATE = new State();
    public static final State ORCHESTRATION_STATE = new State();
    private static final Subject TEST_SUBJECT = new Subject();
    private static final String TEST_INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static final String TEST_RP_SECTOR_HOST = "test.com";

    private static String base64EncodedSalt;
    private static String rpPairwiseId;

    @BeforeEach
    void setup() {
        ipvStub.init();
        configurationService =
                new IPVCallbackHandlerIntegrationTest.TestConfigurationService(
                        ipvStub, externalTokenSigner, ipvPrivateKeyJwtSigner, spotQueue);
        handler = new IPVCallbackHandler(configurationService);
        txmaAuditQueue.clear();
        spotQueue.clear();

        setupClientStore();

        var salt = SaltHelper.generateNewSalt();
        base64EncodedSalt = Base64.getEncoder().encodeToString(salt);
        var internalCommonSubjectId =
                calculatePairwiseIdentifier(
                        TEST_SUBJECT.getValue(), TEST_INTERNAL_SECTOR_HOST, salt);
        rpPairwiseId =
                calculatePairwiseIdentifier(TEST_SUBJECT.getValue(), TEST_RP_SECTOR_HOST, salt);

        setupOrchSession(internalCommonSubjectId);
        setupAuthUserInfoTable(internalCommonSubjectId);
    }

    @Test
    void shouldRedirectToLoginWhenSuccessfullyProcessedIpvResponse() throws Json.JsonException {
        var sectorId = "test.com";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);
        stateStorageExtension.storeState("state:" + SESSION_ID, ORCHESTRATION_STATE.getValue());
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                        IPV_SPOT_REQUESTED));

        SpotQueueAssertionHelper.assertSpotRequestReceived(
                spotQueue,
                List.of(
                        new SPOTRequest(
                                Map.of(
                                        VOT.getValue(),
                                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                        VTM.getValue(),
                                        "/trustmark"),
                                TEST_SUBJECT.getValue(),
                                base64EncodedSalt,
                                sectorId,
                                rpPairwiseId,
                                new LogIds(
                                        SESSION_ID,
                                        PERSISTENT_SESSION_ID,
                                        "request-i",
                                        CLIENT_ID,
                                        CLIENT_SESSION_ID),
                                CLIENT_ID)));

        var identityCredentials =
                identityStore.getIdentityCredentials(CLIENT_SESSION_ID).orElseThrow();
        var additionalClaims = identityCredentials.getAdditionalClaims();

        assertThat(
                additionalClaims.keySet(),
                hasItems(
                        ValidClaims.ADDRESS.getValue(),
                        ValidClaims.PASSPORT.getValue(),
                        ValidClaims.DRIVING_PERMIT.getValue(),
                        ValidClaims.RETURN_CODE.getValue()));

        var addressClaim =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.ADDRESS.getValue()), JSONArray.class);
        assertThat(((LinkedTreeMap) addressClaim.get(0)).size(), equalTo(8));

        var passportClaim =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.PASSPORT.getValue()), JSONArray.class);
        assertThat(((LinkedTreeMap) passportClaim.get(0)).size(), equalTo(2));

        var drivingPermit =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.DRIVING_PERMIT.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) drivingPermit.get(0)).size(), equalTo(6));

        var returnCode =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.RETURN_CODE.getValue()), JSONArray.class);
        assertThat(returnCode.size(), equalTo(2));
    }

    @Test
    void shouldRedirectToRPWhenSuccessfullyProcessedIpvResponseAndSyncWaitForSPOT()
            throws Exception {
        enableSyncWaitForSPOT();
        var sectorId = "test.com";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);
        stateStorageExtension.storeState("state:" + SESSION_ID, ORCHESTRATION_STATE.getValue());
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        startSPOTProcessingThread();
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), startsWith(REDIRECT_URI));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        IPV_AUTHORISATION_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                        IPV_SPOT_REQUESTED,
                        PROCESSING_IDENTITY_REQUEST,
                        AUTH_CODE_ISSUED));

        SpotQueueAssertionHelper.assertSpotRequestReceived(
                spotQueue,
                List.of(
                        new SPOTRequest(
                                Map.of(
                                        VOT.getValue(),
                                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                                        VTM.getValue(),
                                        "/trustmark"),
                                TEST_SUBJECT.getValue(),
                                base64EncodedSalt,
                                sectorId,
                                rpPairwiseId,
                                new LogIds(
                                        SESSION_ID,
                                        PERSISTENT_SESSION_ID,
                                        "request-i",
                                        CLIENT_ID,
                                        CLIENT_SESSION_ID),
                                CLIENT_ID)));

        var identityCredentials =
                identityStore.getIdentityCredentials(CLIENT_SESSION_ID).orElseThrow();
        var additionalClaims = identityCredentials.getAdditionalClaims();

        assertThat(
                additionalClaims.keySet(),
                hasItems(
                        ValidClaims.ADDRESS.getValue(),
                        ValidClaims.PASSPORT.getValue(),
                        ValidClaims.DRIVING_PERMIT.getValue(),
                        ValidClaims.RETURN_CODE.getValue()));

        var addressClaim =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.ADDRESS.getValue()), JSONArray.class);
        assertThat(((LinkedTreeMap) addressClaim.get(0)).size(), equalTo(8));

        var passportClaim =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.PASSPORT.getValue()), JSONArray.class);
        assertThat(((LinkedTreeMap) passportClaim.get(0)).size(), equalTo(2));

        var drivingPermit =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.DRIVING_PERMIT.getValue()),
                        JSONArray.class);
        assertThat(((LinkedTreeMap) drivingPermit.get(0)).size(), equalTo(6));

        var returnCode =
                objectMapper.readValue(
                        additionalClaims.get(ValidClaims.RETURN_CODE.getValue()), JSONArray.class);
        assertThat(returnCode.size(), equalTo(2));
    }

    private void enableSyncWaitForSPOT() {
        configurationService =
                new TestConfigurationService(
                        ipvStub, externalTokenSigner, ipvPrivateKeyJwtSigner, spotQueue, true);
        handler = new IPVCallbackHandler(configurationService);
    }

    private void startSPOTProcessingThread() {
        new Thread(
                        () -> {
                            // Need to wait for identity credentials to be added by handler first!
                            // Else we add the coreIdentityJWT and it gets overwritten by the
                            // handler.
                            var identity = identityStore.getIdentityCredentials(CLIENT_SESSION_ID);
                            while (identity.isEmpty()) {
                                identity = identityStore.getIdentityCredentials(CLIENT_SESSION_ID);
                            }
                            identityStore.addCoreIdentityJWT(
                                    CLIENT_SESSION_ID, "test-subject-id", "test-core-identity-jwt");
                        })
                .start();
    }

    @Test
    void shouldSendCorrectRawStringToSpot() {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);
        stateStorageExtension.storeState("state:" + SESSION_ID, ORCHESTRATION_STATE.getValue());
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        makeRequest(
                Optional.empty(),
                Map.of(
                        "Cookie",
                        format(
                                "gs=%s.%s;di-persistent-session-id=%s",
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                new HashMap<>(
                        Map.of(
                                "state",
                                ORCHESTRATION_STATE.getValue(),
                                "code",
                                new AuthorizationCode().getValue())));

        await().atMost(1, SECONDS)
                .untilAsserted(
                        () -> assertThat(spotQueue.getApproximateMessageCount(), equalTo(1)));

        var rawSpotRequest = spotQueue.getRawMessages();

        assertEquals(
                rawSpotRequest.get(0),
                "{\"in_claims\":{\"https://vocab.account.gov.uk/v1/coreIdentity\":{\"name\":[{\"nameParts\":[{\"type\":\"GivenName\",\"value\":\"kenneth\"},{\"type\":\"FamilyName\",\"value\":\"decerqueira\"}]}],\"birthDate\":[{\"value\":\"1964-11-07\"}]},\"https://vocab.account.gov.uk/v1/credentialJWT\":[\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1hZGRyZXNzLWZyb250LmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbCIsInN1YiI6InVybjpmZGM6Z292LnVrOjIwMjI6XzM5VVBHaU1KakVWUG9faEZVcGRqNmRuUVdaM2RLRHZZeVM4TVl6XzIzQSIsIm5iZiI6MTY1NDg2NzE2MSwiZXhwIjoxNjU0ODY5ODYxLCJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJhZGRyZXNzIjpbeyJ1cHJuIjpudWxsLCJidWlsZGluZ051bWJlciI6IjgiLCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJhZGRyZXNzQ291bnRyeSI6IkdCIiwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBZGRyZXNzQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczpcL1wvd3d3LnczLm9yZ1wvMjAxOFwvY3JlZGVudGlhbHNcL3YxIiwiaHR0cHM6XC9cL3ZvY2FiLmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbFwvY29udGV4dHNcL2lkZW50aXR5LXYxLmpzb25sZCJdfX0.MEUCIEjlQYJ_Tp5sH_twF6FNhByRqyEq_6VOUWV8DpLoYs2FAiEA-om1BW1HXy2y-elaK98N109FVDxHSVmz-WyLfU1Laq8\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1mcmF1ZC1mcm9udC5sb25kb24uY2xvdWRhcHBzLmRpZ2l0YWwiLCJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOl8zOVVQR2lNSmpFVlBvX2hGVXBkajZkblFXWjNkS0R2WXlTOE1Zel8yM0EiLCJuYmYiOjE2NTQ4NjcxODQsImV4cCI6MTY1NDg2OTg4NCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NjQtMTEtMDcifV0sImFkZHJlc3MiOlt7ImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJhZGRyZXNzVHlwZSI6IkNVUlJFTlQiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoia2VubmV0aCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6ImRlY2VycXVlaXJhIn1dfV19LCJldmlkZW5jZSI6W3sidHhuIjoiUkIwMDAwOTk3MDI2MTYiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsImlkZW50aXR5RnJhdWRTY29yZSI6MSwiY2kiOltdfV0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.MEYCIQD5ClbV90UKbTBle9UzWvgq1SdiwKlw1-K2W03pMgv5iwIhAK0sr2ebq8Bac0vGARafUZrhy2RraWf53MP0pmAy-_g2\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvaW50ZWdyYXRpb24tZGktaXB2LWNyaS1rYnYtZnJvbnQubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsIiwic3ViIjoidXJuOmZkYzpnb3YudWs6MjAyMjpfMzlVUEdpTUpqRVZQb19oRlVwZGo2ZG5RV1ozZEtEdll5UzhNWXpfMjNBIiwibmJmIjoxNjU0ODY3MzUwLCJleHAiOjE2NTQ4NzAwNTAsInZjIjp7ImV2aWRlbmNlIjpbeyJ0eG4iOiI3SkFRSjRGQzRHIiwidmVyaWZpY2F0aW9uU2NvcmUiOjIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Imtlbm5ldGgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJkZWNlcnF1ZWlyYSJ9XX1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwidXBybiI6bnVsbCwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9LHsidXBybiI6bnVsbCwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NC0xMS0wNyJ9XX0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.MEQCICA_FEuk_sVCfqQLS2FKnxCEkaH8KOtKE1RbqwzrMKPQAiBKy2V_u0ZQ5O1fwaww6WTZhZUk2k0f5abLDB48ViwjKg\",\"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46ZmRjOmdvdi51azoyMDIyOl8zOVVQR2lNSmpFVlBvX2hGVXBkajZkblFXWjNkS0R2WXlTOE1Zel8yM0EiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTQ4NjcwODYsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1NDg2OTQ4NiwidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIzMjY3NzY2NC1mMGRkLTQ4YWQtYjY1NC03MzYzNGMwZTJkMmIiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoia2VubmV0aCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6ImRlY2VycXVlaXJhIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTY0LTExLTA3In1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEUCIQD3z0rGb7YPFvOKt7p-tlkarsU16lpuOzcdlyNP3WutHgIgfbP0zxvHFAS54VGbnpumfTAxvMM1dsVhfje-2xWTQ0I\"],\"vot\":\"P2\",\"vtm\":\"http://localhost/trustmark\"},"
                        + "\"in_local_account_id\":\""
                        + TEST_SUBJECT.getValue()
                        + "\",\"in_salt\":"
                        + SerializationService.getInstance().writeValueAsString(base64EncodedSalt)
                        + ",\"in_rp_sector_id\":\"test.com\","
                        + "\"out_sub\":\""
                        + rpPairwiseId
                        + "\",\"log_ids\":{\"session_id\":\"some-session-id\""
                        + ",\"persistent_session_id\":\""
                        + PERSISTENT_SESSION_ID
                        + "\",\"request_id\":null,\"client_id\":\"test-client-id\",\"client_session_id\":\"some-client-session-id\"},\"out_audience\":\"test-client-id\"}");
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity() {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        emptyMap(),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "error",
                                        "access_denied")));

        var error =
                new ErrorObject(
                        OAuth2Error.ACCESS_DENIED_CODE,
                        "Access denied for security reasons, a new authentication request may be successful");

        var expectedURI =
                new AuthenticationErrorResponse(URI.create(REDIRECT_URI), error, RP_STATE, null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get(ResponseHeaders.LOCATION), equalTo(expectedURI));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, singletonList(IPV_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED));
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButClientSessionNotFoundWithGivenState() {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);

        var response =
                makeRequest(
                        Optional.empty(),
                        emptyMap(),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "error",
                                        "access_denied")));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldStoreReturnCodesInDynamoWhenTheyArePresent(boolean validLoC)
            throws Json.JsonException {
        if (validLoC) {
            ipvStub.initWithValidLoCAndReturnCode();
        } else {
            ipvStub.initWithInvalidLoCAndReturnCode();
        }

        var scope = new Scope(OIDCScopeValue.OPENID);
        var oidcValidClaimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest().add(ValidClaims.RETURN_CODE.getValue()));
        var authRequest = createAuthRequestBuilder(scope).claims(oidcValidClaimsRequest).build();
        setupClientSession(authRequest);
        stateStorageExtension.storeState("state:" + SESSION_ID, ORCHESTRATION_STATE.getValue());
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        var identityCredentials = identityStore.getIdentityCredentials(CLIENT_SESSION_ID);

        assertThat(response, hasStatus(302));
        if (validLoC) {
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            IPV_AUTHORISATION_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                            IPV_SPOT_REQUESTED));
        } else {
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION), startsWith(REDIRECT_URI));

            assertTxmaAuditEventsReceived(
                    txmaAuditQueue,
                    List.of(
                            IPV_AUTHORISATION_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                            IPV_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
                            AUTH_CODE_ISSUED));

            assertSessionUpdatedWhenReturnCodeRequestedAndPresent();
        }

        assertTrue(
                identityCredentials
                        .map(OrchIdentityCredentials::getAdditionalClaims)
                        .map(t -> t.get(ValidClaims.RETURN_CODE.getValue()))
                        .isPresent());
        var returnCode =
                objectMapper.readValue(
                        identityCredentials
                                .get()
                                .getAdditionalClaims()
                                .get(ValidClaims.RETURN_CODE.getValue()),
                        JSONArray.class);
        assertThat(returnCode.size(), equalTo(1));
    }

    @Test
    void shouldBypassSPoTAndReturnAuthCodeIfIPVReturnsP0ButReturnCodeIsPresentAndRequested() {
        ipvStub.initWithInvalidLoCAndReturnCode();

        var scope = new Scope(OIDCScopeValue.OPENID);
        var oidcValidClaimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest().add(ValidClaims.RETURN_CODE.getValue()));
        var authRequest = createAuthRequestBuilder(scope).claims(oidcValidClaimsRequest).build();
        setupClientSession(authRequest);
        stateStorageExtension.storeState("state:" + SESSION_ID, ORCHESTRATION_STATE.getValue());
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));

        assertThat(spotQueue.getApproximateMessageCount(), equalTo(0));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(REDIRECT_URI + "?code"));
        assertSessionUpdatedWhenReturnCodeRequestedAndPresent();

        assertOrchAuthCodeSaved(orchAuthCodeExtension, response);
    }

    @Test
    void
            shouldBypassSPoTAndReturnAccessDeniedErrorIfIPVReturnsP0AndReturnCodeIsPresentButNotRequested() {
        ipvStub.initWithInvalidLoCAndReturnCode();

        var sessionId = "some-session-id";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var authRequest = createAuthRequestBuilder(scope).build();
        setupClientSession(authRequest);
        crossBrowserStorageExtension.store(ORCHESTRATION_STATE, CLIENT_SESSION_ID);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(
                                "Cookie",
                                format(
                                        "gs=%s.%s;di-persistent-session-id=%s",
                                        sessionId, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID)),
                        new HashMap<>(
                                Map.of(
                                        "state",
                                        ORCHESTRATION_STATE.getValue(),
                                        "code",
                                        new AuthorizationCode().getValue())));

        assertThat(response, hasStatus(302));

        assertThat(spotQueue.getApproximateMessageCount(), equalTo(0));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(REDIRECT_URI + "?error=access_denied"));
    }

    private void setupClientStore() {
        clientStore
                .createClient()
                .withClientId(CLIENT_ID)
                .withClientName("test-client")
                .withRedirectUris(singletonList(REDIRECT_URI))
                .withContacts(singletonList(EMAIL))
                .withSubjectType("pairwise")
                .withClaims(singletonList("https://vocab.account.gov.uk/v1/returnCode"))
                .saveToDynamo();
    }

    private void setupOrchSession(String internalCommonSubjectId) {
        orchSessionExtension.addSession(
                new OrchSessionItem(SESSION_ID)
                        .withVerifiedMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                        .withInternalCommonSubjectId(internalCommonSubjectId));
    }

    private void setupClientSession(AuthenticationRequest authRequest) {
        orchClientSessionExtension.storeClientSession(
                new OrchClientSessionItem(
                                CLIENT_SESSION_ID,
                                authRequest.toParameters(),
                                LocalDateTime.now(),
                                List.of(VectorOfTrust.getDefaults()),
                                CLIENT_NAME)
                        .withRpPairwiseId(rpPairwiseId));
    }

    private AuthenticationRequest.Builder createAuthRequestBuilder(Scope scope) {
        return new AuthenticationRequest.Builder(
                        ResponseType.CODE, scope, new ClientID(CLIENT_ID), URI.create(REDIRECT_URI))
                .nonce(new Nonce())
                .state(RP_STATE);
    }

    private void setupAuthUserInfoTable(String internalCommonSubjectId) {
        var userInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub",
                                        internalCommonSubjectId,
                                        "email",
                                        TEST_EMAIL_ADDRESS,
                                        "phone_number",
                                        TEST_PHONE_NUMBER,
                                        "salt",
                                        base64EncodedSalt,
                                        "local_account_id",
                                        TEST_SUBJECT.getValue())));

        userInfoStorageExtension.addAuthenticationUserInfoData(
                internalCommonSubjectId, CLIENT_SESSION_ID, userInfo);
    }

    private void assertSessionUpdatedWhenReturnCodeRequestedAndPresent() {
        var orchSession = orchSessionExtension.getSession(SESSION_ID).get();

        assertTrue(orchSession.getAuthenticated());
        assertThat(orchSession.getIsNewAccount(), equalTo(OrchSessionItem.AccountState.EXISTING));
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final IPVStubExtension ipvStubExtension;
        private final boolean isSyncWaitForSPOTEnabled;

        public TestConfigurationService(
                IPVStubExtension ipvStub,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue) {
            this(ipvStub, tokenSigningKey, ipvPrivateKeyJwtSigner, spotQueue, false);
        }

        public TestConfigurationService(
                IPVStubExtension ipvStub,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                boolean isSyncWaitForSPOTEnabled) {
            super(
                    tokenSigningKey,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.ipvStubExtension = ipvStub;
            this.isSyncWaitForSPOTEnabled = isSyncWaitForSPOTEnabled;
        }

        @Override
        public URI getIPVBackendURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(ipvStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getIPVAudience() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(ipvStubExtension.getHttpPort())
                        .setScheme("http")
                        .build()
                        .toString();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getIPVAuthorisationClientId() {
            return "ipv-client-id";
        }

        @Override
        public URI getIPVAuthorisationCallbackURI() {
            return URI.create("http://localhost/redirect");
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }

        @Override
        public boolean isSyncWaitForSpotEnabled() {
            return isSyncWaitForSPOTEnabled;
        }
    }
}
