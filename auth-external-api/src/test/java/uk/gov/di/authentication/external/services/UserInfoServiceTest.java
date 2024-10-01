package uk.gov.di.authentication.external.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserInfoServiceTest {
    private UserInfoService userInfoService;
    private ConfigurationService configurationService;
    private AuthenticationService authenticationService;
    public static final ByteBuffer TEST_SALT = ByteBuffer.allocate(10);
    private static final Subject TEST_SUBJECT = new Subject();
    private static final String TEST_RP_SECTOR_HOST = "test-rp-sector-uri";
    private static final String TEST_RP_PAIRWISE_ID =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_SUBJECT.getValue(),
                    TEST_RP_SECTOR_HOST,
                    SdkBytes.fromByteBuffer(TEST_SALT).asByteArray());
    private static final String TEST_INTERNAL_SECTOR_URI = "https://test-internal-sector-uri";
    private static final String TEST_INTERNAL_SECTOR_HOST = "test-internal-sector-uri";
    private static final String TEST_INTERNAL_PAIRWISE_ID =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_SUBJECT.getValue(),
                    TEST_INTERNAL_SECTOR_HOST,
                    SdkBytes.fromByteBuffer(TEST_SALT).asByteArray());
    private static final String TEST_LEGACY_SUBJECT_ID = "test-legacy-subject-id";
    private static final String TEST_PUBLIC_SUBJECT_ID = "test-public-subject-id";
    private static final String TEST_EMAIL = "test-email";
    private static final boolean TEST_EMAIL_VERIFIED = true;
    private static final String TEST_PHONE = "test-phone";
    private static final boolean TEST_PHONE_VERIFIED = true;
    private static final boolean TEST_IS_NEW_ACCOUNT = true;
    private static final long TEST_PASSWORD_RESET_TIME = 1710255380L;
    private static final UserProfile TEST_USER_PROFILE =
            new UserProfile()
                    .withLegacySubjectID(TEST_LEGACY_SUBJECT_ID)
                    .withPublicSubjectID(TEST_PUBLIC_SUBJECT_ID)
                    .withSubjectID(TEST_SUBJECT.getValue())
                    .withEmail(TEST_EMAIL)
                    .withEmailVerified(TEST_EMAIL_VERIFIED)
                    .withPhoneNumber(TEST_PHONE)
                    .withPhoneNumberVerified(TEST_PHONE_VERIFIED)
                    .withSalt(TEST_SALT);
    private static final AuthSessionItem authSession = new AuthSessionItem();

    @BeforeEach
    public void setUp() {
        authenticationService = mock(DynamoService.class);
        configurationService = mock(ConfigurationService.class);
        userInfoService = new UserInfoService(authenticationService, configurationService);

        when(authenticationService.getUserProfileFromSubject(TEST_SUBJECT.getValue()))
                .thenReturn(TEST_USER_PROFILE);
        when(authenticationService.getOrGenerateSalt(TEST_USER_PROFILE)).thenCallRealMethod();
        when(configurationService.getInternalSectorUri()).thenReturn(TEST_INTERNAL_SECTOR_URI);
    }

    @ParameterizedTest
    @MethodSource("provideTestData")
    void shouldReturnUserInfoLimitedToClaimsInAccessTokenStore(
            AccessTokenStore mockAccessTokenStore,
            String expectedLegacySubjectId,
            String expectedPublicSubjectId,
            String expectedLocalAccountId,
            String expectedEmailAddress,
            Boolean expectedEmailVerified,
            String expectedPhoneNumber,
            Boolean expectedPhoneNumberVerified,
            String expectedSalt) {
        UserInfo actual = userInfoService.populateUserInfo(mockAccessTokenStore, authSession);

        assertEquals(TEST_INTERNAL_PAIRWISE_ID, actual.getSubject().getValue());
        assertEquals(TEST_RP_PAIRWISE_ID, actual.getClaim("rp_pairwise_id"));
        assertEquals(TEST_IS_NEW_ACCOUNT, actual.getClaim("new_account"));

        assertEquals(expectedLegacySubjectId, actual.getClaim("legacy_subject_id"));
        assertEquals(expectedPublicSubjectId, actual.getClaim("public_subject_id"));
        assertEquals(expectedLocalAccountId, actual.getClaim("local_account_id"));
        assertEquals(expectedEmailAddress, actual.getEmailAddress());
        assertEquals(expectedEmailVerified, actual.getEmailVerified());
        assertEquals(expectedPhoneNumber, actual.getPhoneNumber());
        assertEquals(expectedPhoneNumberVerified, actual.getPhoneNumberVerified());
        assertEquals(expectedSalt, actual.getClaim("salt"));
        assertEquals(TEST_PASSWORD_RESET_TIME, actual.getClaim("password_reset_time"));
    }

    private static Stream<Arguments> provideTestData() {
        return Stream.of(
                Arguments.of(
                        getMockAccessTokenStore(List.of("local_account_id")),
                        null,
                        null,
                        TEST_SUBJECT.getValue(),
                        null,
                        null,
                        null,
                        null,
                        null),
                Arguments.of(
                        getMockAccessTokenStore(
                                List.of("legacy_subject_id", "email", "email_verified")),
                        TEST_LEGACY_SUBJECT_ID,
                        null,
                        null,
                        TEST_EMAIL,
                        TEST_EMAIL_VERIFIED,
                        null,
                        null,
                        null),
                Arguments.of(
                        getMockAccessTokenStore(
                                List.of(
                                        "legacy_subject_id",
                                        "public_subject_id",
                                        "local_account_id",
                                        "email",
                                        "email_verified",
                                        "phone_number",
                                        "phone_number_verified",
                                        "salt")),
                        TEST_LEGACY_SUBJECT_ID,
                        TEST_PUBLIC_SUBJECT_ID,
                        TEST_SUBJECT.getValue(),
                        TEST_EMAIL,
                        TEST_EMAIL_VERIFIED,
                        TEST_PHONE,
                        TEST_PHONE_VERIFIED,
                        bytesToBase64(TEST_SALT)));
    }

    private static AccessTokenStore getMockAccessTokenStore(List<String> claims) {
        var accessTokenStore = mock(AccessTokenStore.class);
        when(accessTokenStore.getSubjectID()).thenReturn(TEST_SUBJECT.getValue());
        when(accessTokenStore.getSectorIdentifier()).thenReturn(TEST_RP_SECTOR_HOST);
        when(accessTokenStore.getIsNewAccount()).thenReturn(TEST_IS_NEW_ACCOUNT);
        when(accessTokenStore.getPasswordResetTime()).thenReturn(TEST_PASSWORD_RESET_TIME);
        when(accessTokenStore.getClaims()).thenReturn(claims);
        return accessTokenStore;
    }

    private static String bytesToBase64(ByteBuffer byteBuffer) {
        ByteBuffer duplicateBuffer = byteBuffer.duplicate();
        byte[] byteArray = new byte[duplicateBuffer.remaining()];
        duplicateBuffer.get(byteArray);
        return Base64.getEncoder().encodeToString(byteArray);
    }
}
