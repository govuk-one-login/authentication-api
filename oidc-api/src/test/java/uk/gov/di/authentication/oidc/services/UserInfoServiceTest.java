package uk.gov.di.authentication.oidc.services;

import com.google.gson.internal.LinkedTreeMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class UserInfoServiceTest {

    private UserInfoService userInfoService;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final DynamoIdentityService identityService = mock(DynamoIdentityService.class);
    private final DynamoDocAppService dynamoDocAppService = mock(DynamoDocAppService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
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
                    .add(ValidClaims.PASSPORT.getValue());
    private final OIDCClaimsRequest oidcValidClaimsRequest =
            new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
    private final String coreIdentityJWT = SignedCredentialHelper.generateCredential().serialize();
    private final String docAppCredentialJWT =
            SignedCredentialHelper.generateCredential().serialize();
    private AccessToken accessToken;
    private ClientRegistry clientRegistry;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UserInfoService.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, SUBJECT.toString()))));
    }

    @BeforeEach
    void setUp() {
        userInfoService =
                new UserInfoService(
                        authenticationService,
                        identityService,
                        dynamoDocAppService,
                        cloudwatchMetricsService,
                        configurationService);
        clientRegistry = generateClientRegistry();
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getEnvironment()).thenReturn("test");
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityNotEnabled() throws JOSEException {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        accessToken = createSignedAccessToken(null);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
    }

    @Test
    void shouldJustPopulateEmailClaimWhenOnlyEmailScopeIsPresentAndIdentityNotEnabled()
            throws JOSEException {
        when(configurationService.isIdentityEnabled()).thenReturn(false);
        accessToken = createSignedAccessToken(null);
        var scopes = List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.EMAIL.getValue());
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), scopes, null, CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertNull(userInfo.getPhoneNumber());
        assertNull(userInfo.getPhoneNumberVerified());
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityEnabledButNoIdentityClaimsPresent()
            throws JOSEException {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        accessToken = createSignedAccessToken(null);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.DRIVING_PERMIT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
    }

    @Test
    void shouldPopulateIdentityClaimsWhenClaimsArePresentAndIdentityIsEnabled()
            throws JOSEException {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(SUBJECT.getValue())
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withAdditionalClaims(
                                Map.of(
                                        ValidClaims.ADDRESS.getValue(),
                                        ADDRESS_CLAIM,
                                        ValidClaims.PASSPORT.getValue(),
                                        PASSPORT_CLAIM,
                                        ValidClaims.DRIVING_PERMIT.getValue(),
                                        PASSPORT_CLAIM));
        accessToken = createSignedAccessToken(oidcValidClaimsRequest);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());
        when(identityService.getIdentityCredentials(SUBJECT.getValue()))
                .thenReturn(Optional.of(identityCredentials));

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore,
                        SUBJECT.getValue(),
                        SCOPES,
                        oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                                .map(ClaimsSetRequest.Entry::getClaimName)
                                .collect(Collectors.toList()),
                        CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertThat(
                userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                equalTo(coreIdentityJWT));
        var addressClaim = (JSONArray) userInfo.getClaim(ValidClaims.ADDRESS.getValue());
        assertThat(((LinkedTreeMap) addressClaim.get(0)).size(), equalTo(7));
        var passportClaim = (JSONArray) userInfo.getClaim(ValidClaims.PASSPORT.getValue());
        assertThat(((LinkedTreeMap) passportClaim.get(0)).size(), equalTo(2));

        assertClaimMetricPublished("https://vocab.account.gov.uk/v1/coreIdentityJWT");
        assertClaimMetricPublished("https://vocab.account.gov.uk/v1/address");
        assertClaimMetricPublished("https://vocab.account.gov.uk/v1/passport");
    }

    @Test
    void shouldPopulateIdentityClaimsWhenClaimsArePresentButNoAdditionalClaimsArePresent()
            throws JOSEException {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(SUBJECT.getValue())
                        .withCoreIdentityJWT(coreIdentityJWT);
        accessToken = createSignedAccessToken(oidcValidClaimsRequest);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());
        when(identityService.getIdentityCredentials(SUBJECT.getValue()))
                .thenReturn(Optional.of(identityCredentials));

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore,
                        SUBJECT.getValue(),
                        SCOPES,
                        oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                                .map(ClaimsSetRequest.Entry::getClaimName)
                                .collect(Collectors.toList()),
                        CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertThat(
                userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                equalTo(coreIdentityJWT));

        assertClaimMetricPublished("https://vocab.account.gov.uk/v1/coreIdentityJWT");
    }

    @Test
    void shouldPopulateUserInfoWithDocAppCredentialWhenDocAppScopeIsPresent() throws JOSEException {
        var docAppScope =
                List.of(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.DOC_CHECKING_APP.getValue());
        var accessToken = createSignedAccessToken(null, docAppScope);
        var docAppCredential =
                new DocAppCredential()
                        .withSubjectID(SUBJECT.getValue())
                        .withCredential(List.of(docAppCredentialJWT));
        when(dynamoDocAppService.getDocAppCredential(SUBJECT.getValue()))
                .thenReturn(Optional.of(docAppCredential));

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore, SUBJECT.getValue(), docAppScope, null, CLIENT_ID);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo);
        assertThat(userInfo.getClaim("doc-app-credential"), equalTo(List.of(docAppCredentialJWT)));
        assertClaimMetricPublished("doc-app-credential");
    }

    @Test
    void shouldReturnInternalCommonSubjectIdentifierWhenDocAppScopeIsNotPresent()
            throws JOSEException {
        var salt = SaltHelper.generateNewSalt();
        var expectedCommonSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", salt);
        accessToken = createSignedAccessToken(null);
        var userProfile = generateUserprofile();
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(userProfile);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null, CLIENT_ID);

        var subjectForAudit = userInfoService.calculateSubjectForAudit(accessTokenInfo);

        assertThat(subjectForAudit, equalTo(expectedCommonSubject));
    }

    @Test
    void shouldReturnDocAppSubjectIdWhenDocAppScopeIsPresent() throws JOSEException {
        accessToken = createSignedAccessToken(null);
        var docAppScope =
                List.of(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.DOC_CHECKING_APP.getValue());
        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), DOC_APP_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore, DOC_APP_SUBJECT.getValue(), docAppScope, null, CLIENT_ID);
        var subjectForAudit = userInfoService.calculateSubjectForAudit(accessTokenInfo);

        assertThat(subjectForAudit, equalTo(DOC_APP_SUBJECT.getValue()));
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

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID)
                .withConsentRequired(false)
                .withClientName("test-client")
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("public");
    }

    private void assertClaimMetricPublished(String v3) {
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "ClaimIssued",
                        Map.of("Environment", "test", "Client", CLIENT_ID, "Claim", v3));
    }
}
