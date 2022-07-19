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
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
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
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class UserInfoServiceTest {

    private UserInfoService userInfoService;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final DynamoIdentityService identityService = mock(DynamoIdentityService.class);
    private final DynamoDocAppService dynamoDocAppService = mock(DynamoDocAppService.class);
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject SUBJECT = new Subject("some-subject");
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
                new UserInfoService(authenticationService, identityService, dynamoDocAppService);
        clientRegistry = generateClientRegistry();
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityNotEnabled() throws JOSEException {
        accessToken = createSignedAccessToken(null);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore, SUBJECT.getValue(), SCOPES, null, clientRegistry);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, false);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
    }

    @Test
    void shouldJustPopulateEmailClaimWhenOnlyEmailScopeIsPresentAndIdentityNotEnabled()
            throws JOSEException {
        accessToken = createSignedAccessToken(null);
        var scopes = List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.EMAIL.getValue());
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore, SUBJECT.getValue(), scopes, null, clientRegistry);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, false);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertNull(userInfo.getPhoneNumber());
        assertNull(userInfo.getPhoneNumberVerified());
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityEnabledButNoIdentityClaimsPresent()
            throws JOSEException {
        accessToken = createSignedAccessToken(null);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore, SUBJECT.getValue(), SCOPES, null, clientRegistry);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, true);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));
    }

    @Test
    void shouldPopulateIdentityClaimsWhenClaimsArePresentAndIdentityIsEnabled()
            throws JOSEException {
        var identityCredentials =
                new IdentityCredentials()
                        .setSubjectID(SUBJECT.getValue())
                        .setCoreIdentityJWT(coreIdentityJWT)
                        .setAdditionalClaims(
                                Map.of(
                                        ValidClaims.ADDRESS.getValue(),
                                        ADDRESS_CLAIM,
                                        ValidClaims.PASSPORT.getValue(),
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
                        clientRegistry);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, true);
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
    }

    @Test
    void shouldPopulateIdentityClaimsWhenClaimsArePresentButNoAdditionalClaimsArePresent()
            throws JOSEException {
        var identityCredentials =
                new IdentityCredentials()
                        .setSubjectID(SUBJECT.getValue())
                        .setCoreIdentityJWT(coreIdentityJWT);
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
                        clientRegistry);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, true);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertThat(
                userInfo.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                equalTo(coreIdentityJWT));
    }

    private AccessToken createSignedAccessToken(OIDCClaimsRequest identityClaims)
            throws JOSEException {
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
                        SCOPES,
                        signer,
                        SUBJECT,
                        ecSigningKey.getKeyID(),
                        expiryDate,
                        identityClaims);
        return new BearerAccessToken(signedJWT.serialize());
    }

    private UserProfile generateUserprofile() {
        return new UserProfile()
                .setEmail("joe.bloggs@digital.cabinet-office.gov.uk")
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setSubjectID(SUBJECT.toString())
                .setCreated(LocalDateTime.now().toString())
                .setUpdated(LocalDateTime.now().toString());
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .setClientID(CLIENT_ID)
                .setConsentRequired(false)
                .setClientName("test-client")
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("public");
    }
}
