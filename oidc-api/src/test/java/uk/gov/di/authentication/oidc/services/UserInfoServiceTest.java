package uk.gov.di.authentication.oidc.services;

import com.google.gson.internal.LinkedTreeMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AuthenticationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.sharedtest.helper.SignedCredentialHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.DRIVING_PERMIT;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.RETURN_CODE;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class UserInfoServiceTest {
    private final AuthenticationUserInfoStorageService userInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private UserInfoService userInfoService;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoIdentityService identityService = mock(DynamoIdentityService.class);
    private final DynamoDocAppCriService dynamoDocAppCriService =
            mock(DynamoDocAppCriService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject INTERNAL_PAIRWISE_SUBJECT = new Subject("test-subject");
    private static final String JOURNEY_ID = "client-session-id";
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final Subject DOC_APP_SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final String CLIENT_ID = "client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest()
                    .add(ValidClaims.CORE_IDENTITY_JWT.getValue())
                    .add(ValidClaims.ADDRESS.getValue())
                    .add(ValidClaims.PASSPORT.getValue())
                    .add(ValidClaims.DRIVING_PERMIT.getValue())
                    .add(ValidClaims.RETURN_CODE.getValue());
    private final OIDCClaimsRequest oidcValidClaimsRequest =
            new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
    private final String coreIdentityJWT = SignedCredentialHelper.generateCredential().serialize();
    private final String docAppCredentialJWT =
            SignedCredentialHelper.generateCredential().serialize();
    private AccessToken accessToken;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UserInfoService.class);

    @BeforeEach
    void setUp() {
        userInfoService =
                new UserInfoService(
                        identityService,
                        dynamoClientService,
                        dynamoDocAppCriService,
                        cloudwatchMetricsService,
                        configurationService,
                        userInfoStorageService);
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getEnvironment()).thenReturn("test");
    }

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, SUBJECT.toString()))));
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityNotEnabled()
            throws JOSEException, AccessTokenException, ClientNotFoundException, ParseException {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        accessToken = createSignedAccessToken(null);
        var accessTokenStore =
                new AccessTokenStore(
                        accessToken.getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue(),
                        JOURNEY_ID);
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);
        givenThereIsUserInfo();

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));
    }

    @Test
    void shouldJustPopulateWalletSubjectIdClaimWhenWalletSubjectIdScopeIsPresent()
            throws JOSEException, AccessTokenException, ClientNotFoundException, ParseException {
        givenThereIsUserInfo();
        when(dynamoClientService.getClient(any()))
                .thenReturn(
                        Optional.of(
                                new ClientRegistry()
                                        .withClientID("test-client")
                                        .withSectorIdentifierUri("https://test.com")));
        var walletSubjectId =
                ClientSubjectHelper.calculateWalletSubjectIdentifier(
                        "test.com", INTERNAL_PAIRWISE_SUBJECT.getValue());
        accessToken = createSignedAccessToken(null);
        var scopes =
                List.of(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.WALLET_SUBJECT_ID.getValue());
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(
                        accessToken.getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue(),
                        JOURNEY_ID);
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), scopes, null, CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

        assertThat(userInfo.getClaim("wallet_subject_id"), equalTo(walletSubjectId));
        assertNull(userInfo.getEmailAddress());
        assertNull(userInfo.getEmailVerified());
        assertNull(userInfo.getPhoneNumber());
        assertNull(userInfo.getPhoneNumberVerified());
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
    }

    @Nested
    class userInfoClaimsTests {

        @Test
        void shouldJustPopulateUserInfoWhenIdentityEnabledButNoIdentityClaimsPresent()
                throws JOSEException,
                        AccessTokenException,
                        ClientNotFoundException,
                        ParseException {
            when(configurationService.isIdentityEnabled()).thenReturn(true);
            accessToken = createSignedAccessToken(null);
            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);
            givenThereIsUserInfo();

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
            assertThat(userInfo.getEmailVerified(), equalTo(true));
            assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
            assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
            assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        }

        @Test
        void shouldPopulateIdentityClaimsWhenClaimsArePresentAndIdentityIsEnabled()
                throws JOSEException,
                        AccessTokenException,
                        ClientNotFoundException,
                        ParseException {
            when(configurationService.isIdentityEnabled()).thenReturn(true);
            var identityCredentials =
                    new OrchIdentityCredentials()
                            .withClientSessionId(JOURNEY_ID)
                            .withSubjectID(SUBJECT.getValue())
                            .withCoreIdentityJWT(coreIdentityJWT)
                            .withAdditionalClaims(
                                    Map.of(
                                            ValidClaims.ADDRESS.getValue(),
                                            ADDRESS_CLAIM,
                                            ValidClaims.PASSPORT.getValue(),
                                            PASSPORT_CLAIM,
                                            ValidClaims.DRIVING_PERMIT.getValue(),
                                            DRIVING_PERMIT,
                                            ValidClaims.RETURN_CODE.getValue(),
                                            RETURN_CODE));
            accessToken = createSignedAccessToken(oidcValidClaimsRequest);

            when(identityService.getIdentityCredentials(JOURNEY_ID))
                    .thenReturn(Optional.of(identityCredentials));

            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore,
                            SUBJECT.getValue(),
                            SCOPES,
                            oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                                    .map(ClaimsSetRequest.Entry::getClaimName)
                                    .collect(Collectors.toList()),
                            CLIENT_ID);
            givenThereIsUserInfo();

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
            assertThat(userInfo.getEmailVerified(), equalTo(true));
            assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
            assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
            assertThat(
                    userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                    equalTo(coreIdentityJWT));
            var addressClaim = (JSONArray) userInfo.getClaim(ValidClaims.ADDRESS.getValue());
            var passportClaim = (JSONArray) userInfo.getClaim(ValidClaims.PASSPORT.getValue());
            var drivingPermitClaim =
                    (JSONArray) userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue());
            var returnCodeClaim = (JSONArray) userInfo.getClaim(ValidClaims.RETURN_CODE.getValue());
            assertThat(((LinkedTreeMap) addressClaim.get(0)).size(), equalTo(7));
            assertThat(((LinkedTreeMap) passportClaim.get(0)).size(), equalTo(2));
            assertThat(((LinkedTreeMap) drivingPermitClaim.get(0)).size(), equalTo(6));
            assertThat(((LinkedTreeMap) returnCodeClaim.get(0)).size(), equalTo(1));

            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/coreIdentityJWT");
            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/address");
            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/passport");
            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/drivingPermit");
            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/returnCode");
        }

        @Test
        void shouldJustPopulateEmailClaimWhenOnlyEmailScopeIsPresentAndIdentityNotEnabled()
                throws JOSEException,
                        AccessTokenException,
                        ClientNotFoundException,
                        ParseException {
            givenThereIsUserInfo();
            when(configurationService.isIdentityEnabled()).thenReturn(false);
            accessToken = createSignedAccessToken(null);
            var scopes = List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.EMAIL.getValue());
            when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                    .thenReturn(generateUserprofile());

            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore, SUBJECT.getValue(), scopes, null, CLIENT_ID);

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
            assertThat(userInfo.getEmailVerified(), equalTo(true));
            assertNull(userInfo.getPhoneNumber());
            assertNull(userInfo.getPhoneNumberVerified());
            assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        }

        @Test
        void shouldJustPopulateEmailClaimWhenOnlyEmailScopeIsPresentAndIdentity()
                throws JOSEException,
                        AccessTokenException,
                        ClientNotFoundException,
                        ParseException {
            when(configurationService.isIdentityEnabled()).thenReturn(false);
            accessToken = createSignedAccessToken(null);
            var scopes = List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.EMAIL.getValue());

            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore, SUBJECT.getValue(), scopes, null, CLIENT_ID);
            givenThereIsUserInfo();

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
            assertThat(userInfo.getEmailVerified(), equalTo(true));
            assertNull(userInfo.getPhoneNumber());
            assertNull(userInfo.getPhoneNumberVerified());
            assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        }

        @Test
        void shouldPopulateIdentityClaimsWhenClaimsArePresentButNoAdditionalClaimsArePresent()
                throws JOSEException,
                        AccessTokenException,
                        ClientNotFoundException,
                        ParseException {
            when(configurationService.isIdentityEnabled()).thenReturn(true);
            var identityCredentials =
                    new OrchIdentityCredentials()
                            .withClientSessionId(JOURNEY_ID)
                            .withSubjectID(SUBJECT.getValue())
                            .withCoreIdentityJWT(coreIdentityJWT);
            accessToken = createSignedAccessToken(oidcValidClaimsRequest);

            when(identityService.getIdentityCredentials(JOURNEY_ID))
                    .thenReturn(Optional.of(identityCredentials));

            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore,
                            SUBJECT.getValue(),
                            SCOPES,
                            oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                                    .map(ClaimsSetRequest.Entry::getClaimName)
                                    .collect(Collectors.toList()),
                            CLIENT_ID);
            givenThereIsUserInfo();

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
            assertThat(userInfo.getEmailVerified(), equalTo(true));
            assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
            assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
            assertThat(
                    userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                    equalTo(coreIdentityJWT));
            assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
            assertNull(userInfo.getClaim(ValidClaims.RETURN_CODE.getValue()));

            assertClaimMetricPublished("https://vocab.account.gov.uk/v1/coreIdentityJWT");
        }
    }

    @Nested
    class docAppTests {

        @Test
        void shouldPopulateUserInfoWithDocAppCredentialWhenDocAppScopeIsPresent()
                throws JOSEException, AccessTokenException, ClientNotFoundException {
            var docAppScope =
                    List.of(
                            OIDCScopeValue.OPENID.getValue(),
                            CustomScopeValue.DOC_CHECKING_APP.getValue());
            var accessToken = createSignedAccessToken(null, docAppScope);
            var docAppCredential =
                    new DocAppCredential()
                            .withSubjectID(SUBJECT.getValue())
                            .withCredential(List.of(docAppCredentialJWT));
            when(dynamoDocAppCriService.getDocAppCredential(SUBJECT.getValue()))
                    .thenReturn(Optional.of(docAppCredential));

            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore, SUBJECT.getValue(), docAppScope, null, CLIENT_ID);

            var userInfo = userInfoService.populateUserInfo(accessTokenInfo);

            assertThat(
                    userInfo.getClaim("doc-app-credential"), equalTo(List.of(docAppCredentialJWT)));
            assertClaimMetricPublished("doc-app-credential");
        }

        @Test
        void shouldReturnDocAppSubjectIdWhenDocAppScopeIsPresent() throws JOSEException {
            accessToken = createSignedAccessToken(null);
            var docAppScope =
                    List.of(
                            OIDCScopeValue.OPENID.getValue(),
                            CustomScopeValue.DOC_CHECKING_APP.getValue());
            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            DOC_APP_SUBJECT.getValue(),
                            DOC_APP_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore,
                            DOC_APP_SUBJECT.getValue(),
                            docAppScope,
                            null,
                            CLIENT_ID);

            var subjectForAudit = userInfoService.calculateSubjectForAudit(accessTokenInfo);

            assertThat(subjectForAudit, equalTo(DOC_APP_SUBJECT.getValue()));
        }

        @Test
        void shouldReturnInternalCommonSubjectIdentifierWhenDocAppScopeIsNotPresent()
                throws JOSEException {
            accessToken = createSignedAccessToken(null);
            var accessTokenStore =
                    new AccessTokenStore(
                            accessToken.getValue(),
                            INTERNAL_SUBJECT.getValue(),
                            INTERNAL_PAIRWISE_SUBJECT.getValue(),
                            JOURNEY_ID);
            var accessTokenInfo =
                    new AccessTokenInfo(
                            accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);

            var subjectForAudit = userInfoService.calculateSubjectForAudit(accessTokenInfo);

            assertThat(subjectForAudit, equalTo(INTERNAL_PAIRWISE_SUBJECT.getValue()));
        }
    }

    private AccessToken createSignedAccessToken(OIDCClaimsRequest identityClaims)
            throws JOSEException {
        return createSignedAccessToken(identityClaims, SCOPES);
    }

    private AccessToken createSignedAccessToken(
            OIDCClaimsRequest identityClaims, List<String> scopes) throws JOSEException {
        var expiryDate = NowHelper.nowPlus(3, ChronoUnit.MINUTES);
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var signer = new ECDSASigner(ecSigningKey);
        var signedJWT =
                TokenGeneratorHelper.generateSignedToken(
                        CLIENT_ID,
                        BASE_URL,
                        scopes,
                        signer,
                        SUBJECT,
                        ecSigningKey.getKeyID(),
                        expiryDate,
                        identityClaims);
        return new BearerAccessToken(signedJWT.serialize());
    }

    private UserInfo generateUserInfo() {
        UserInfo userInfo = new UserInfo(INTERNAL_SUBJECT);
        userInfo.setEmailAddress(EMAIL);
        userInfo.setEmailVerified(true);
        userInfo.setPhoneNumber(PHONE_NUMBER);
        userInfo.setPhoneNumberVerified(true);
        return userInfo;
    }

    private UserProfile generateUserprofile() {
        return new UserProfile()
                .withEmail("joe.bloggs@digital.cabinet-office.gov.uk")
                .withEmailVerified(true)
                .withPhoneNumber(PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withSubjectID(INTERNAL_SUBJECT.toString())
                .withCreated(LocalDateTime.now().toString())
                .withUpdated(LocalDateTime.now().toString());
    }

    private void assertClaimMetricPublished(String v3) {
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ClaimIssued",
                        Map.of("Environment", "test", "Client", CLIENT_ID, "Claim", v3));
    }

    private void givenThereIsUserInfo() throws ParseException {
        var testUserInfo = generateUserInfo();

        when(userInfoStorageService.getAuthenticationUserInfo(
                        INTERNAL_PAIRWISE_SUBJECT.getValue(), JOURNEY_ID))
                .thenReturn(Optional.of(testUserInfo));
    }
}
