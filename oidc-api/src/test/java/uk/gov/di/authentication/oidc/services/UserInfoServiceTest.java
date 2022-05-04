package uk.gov.di.authentication.oidc.services;

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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.SPOTCredential;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.DynamoSpotService;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class UserInfoServiceTest {

    private UserInfoService userInfoService;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final DynamoSpotService spotService = mock(DynamoSpotService.class);
    private final DynamoDocAppService dynamoDocAppService = mock(DynamoDocAppService.class);

    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final String ADDRESS_CLAIM = "some-address";
    private static final String PASSPORT_NUMBER_CLAIM = "123456789";
    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final String CLIENT_ID = "client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest().add(ValidClaims.ADDRESS).add(ValidClaims.PASSPORT_NUMBER);
    private final OIDCClaimsRequest oidcValidClaimsRequest =
            new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
    private final String serializedCredential =
            SignedCredentialHelper.generateCredential().serialize();
    private final SPOTCredential spotCredential =
            new SPOTCredential()
                    .setSubjectID(SUBJECT.getValue())
                    .setSerializedCredential(serializedCredential)
                    .setAddress(ADDRESS_CLAIM)
                    .setPassportNumber(PASSPORT_NUMBER_CLAIM);
    private AccessToken accessToken;

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
                new UserInfoService(authenticationService, spotService, dynamoDocAppService);
    }

    @Test
    void shouldJustPopulateUserInfoWhenIdentityNotEnabled() throws JOSEException {
        accessToken = createSignedAccessToken(null);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, false);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim("address"));
        assertNull(userInfo.getClaim("passport-number"));
        assertNull(userInfo.getClaim("identity"));
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
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), scopes, null);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, false);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertNull(userInfo.getPhoneNumber());
        assertNull(userInfo.getPhoneNumberVerified());
        assertNull(userInfo.getClaim("address"));
        assertNull(userInfo.getClaim("passport-number"));
        assertNull(userInfo.getClaim("identity"));
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
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES, null);

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, true);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertNull(userInfo.getClaim("address"));
        assertNull(userInfo.getClaim("passport-number"));
        assertNull(userInfo.getClaim("identity"));
    }

    @Test
    void shouldPopulateIdentityClaimsWhenClaimsArePresentAndIdentityIsEnabled()
            throws JOSEException {
        accessToken = createSignedAccessToken(oidcValidClaimsRequest);
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());
        when(spotService.getSpotCredential(SUBJECT.getValue()))
                .thenReturn(Optional.of(spotCredential));

        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenInfo =
                new AccessTokenInfo(
                        accessTokenStore,
                        SUBJECT.getValue(),
                        SCOPES,
                        oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                                .map(ClaimsSetRequest.Entry::getClaimName)
                                .collect(Collectors.toList()));

        var userInfo = userInfoService.populateUserInfo(accessTokenInfo, true);
        assertThat(userInfo.getEmailAddress(), equalTo(EMAIL));
        assertThat(userInfo.getEmailVerified(), equalTo(true));
        assertThat(userInfo.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(userInfo.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfo.getClaim("address"), equalTo(ADDRESS_CLAIM));
        assertThat(userInfo.getClaim("passport-number"), equalTo(PASSPORT_NUMBER_CLAIM));
        assertThat(userInfo.getClaim("identity"), equalTo(serializedCredential));
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
}
