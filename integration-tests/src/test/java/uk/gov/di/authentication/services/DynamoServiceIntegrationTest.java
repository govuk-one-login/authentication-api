package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.time.LocalDateTime;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class DynamoServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String UPDATED_TEST_EMAIL = "user.one@test.com";
    private static final String CLIENT_ID = "client-id";
    private static final LocalDateTime CREATED_DATE_TIME = LocalDateTime.now();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final Set<String> CLAIMS =
            ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
    private static final ClientConsent CLIENT_CONSENT =
            new ClientConsent(CLIENT_ID, CLAIMS, CREATED_DATE_TIME.toString());

    private static final String TEST_MFA_APP_CREDENTIAL = "test-mfa-app-credential";

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());

    @Test
    void getOrGenerateSaltShouldReturnNewSaltWhenUserDoesNotHaveOne() {
        setUpDynamo();
        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt.length, equalTo(32));
        assertThat(SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray(), equalTo(salt));
        UserProfile savedProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        assertThat(SdkBytes.fromByteBuffer(savedProfile.getSalt()).asByteArray(), equalTo(salt));
    }

    @Test
    void getOrGenerateSaltShouldReturnExistingSaltWhenOneExists() {
        setUpDynamo();
        byte[] existingSalt = userStore.addSalt(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt, equalTo(existingSalt));
        UserProfile savedProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        assertThat(
                existingSalt,
                equalTo(SdkBytes.fromByteBuffer(savedProfile.getSalt()).asByteArray()));
    }

    private void setUpDynamo() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItems() {
        setUpDynamo();

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithAccountVerified() {
        setUpDynamo();
        dynamoService.setAccountVerified(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithAccountVerifiedForAccountRecovery() {
        setUpDynamo();
        dynamoService.setAccountVerifiedForAccountRecovery(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithSalt() {
        setUpDynamo();
        userStore.addSalt(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithConsents() {
        setUpDynamo();

        dynamoService.updateConsent(TEST_EMAIL, CLIENT_CONSENT);
        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithMfaMethods() {
        setUpDynamo();

        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, false, true, TEST_MFA_APP_CREDENTIAL);
        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldHaveZeroConsentsAfterSignUp() {
        setUpDynamo();
        UserProfile userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);

        assertThat(userProfile.getClientConsent(), equalTo(null));
    }

    @Test
    void shouldAddAuthAppMFAMethod() {
        setUpDynamo();
        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        MFAMethod mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(true));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
    }

    @Test
    void shouldAddAuthAppMFAMethodForAccountRecovery() {
        setUpDynamo();
        dynamoService.updateMFAMethodForAccountRecovery(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        MFAMethod mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(true));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
    }

    @Test
    void shoulSetAuthAppMFAMethodNotEnabled() {
        setUpDynamo();
        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.setMFAMethodEnabled(TEST_EMAIL, MFAMethodType.AUTH_APP, false);
        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        MFAMethod mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(false));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
    }

    @Test
    void shoulSetAuthAppMFAMethodNotEnabledForAccountRecovery() {
        setUpDynamo();
        dynamoService.updateMFAMethodForAccountRecovery(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.setMFAMethodEnabledForAccountRecovery(TEST_EMAIL, MFAMethodType.AUTH_APP, false);
        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        MFAMethod mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(false));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
    }

    private void testUpdateEmail(UserProfile userProfile, UserCredentials userCredentials) {
        dynamoService.updateEmail(TEST_EMAIL, UPDATED_TEST_EMAIL, CREATED_DATE_TIME);

        UserProfile updatedUserProfile =
                dynamoService.getUserProfileByEmailMaybe(UPDATED_TEST_EMAIL).orElseThrow();

        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(UPDATED_TEST_EMAIL);

        assertThat(updatedUserProfile.getEmail(), equalTo(UPDATED_TEST_EMAIL));
        assertThat(updatedUserCredentials.getEmail(), equalTo(UPDATED_TEST_EMAIL));

        assertThat(updatedUserProfile.getUpdated(), equalTo(CREATED_DATE_TIME.toString()));
        assertThat(updatedUserCredentials.getUpdated(), equalTo(CREATED_DATE_TIME.toString()));

        compareUserProfiles(userProfile, updatedUserProfile);
        compareUserCredentials(userCredentials, updatedUserCredentials);

        assertThat(dynamoService.getUserProfileByEmail(TEST_EMAIL), equalTo(null));
        assertThat(dynamoService.getUserCredentialsFromEmail(TEST_EMAIL), equalTo(null));
    }

    private void compareUserProfiles(UserProfile before, UserProfile after) {
        assertThat(before.getPhoneNumber(), equalTo(after.getPhoneNumber()));
        assertThat(before.isPhoneNumberVerified(), equalTo(after.isPhoneNumberVerified()));
        assertThat(before.isEmailVerified(), equalTo(after.isEmailVerified()));
        assertThat(before.getCreated(), equalTo(after.getCreated()));
        assertThat(before.getSubjectID(), equalTo(after.getSubjectID()));
        assertThat(before.getLegacySubjectID(), equalTo(after.getLegacySubjectID()));
        assertThat(before.getPublicSubjectID(), equalTo(after.getPublicSubjectID()));
        assertThat(before.getSalt(), equalTo(after.getSalt()));
        assertThat(before.getClientConsent(), equalTo(after.getClientConsent()));
        assertThat(before.getTermsAndConditions(), equalTo(after.getTermsAndConditions()));
    }

    private void compareUserCredentials(UserCredentials before, UserCredentials after) {
        assertThat(before.getPassword(), equalTo(after.getPassword()));
        assertThat(before.getMigratedPassword(), equalTo(after.getMigratedPassword()));
        assertThat(before.getSubjectID(), equalTo(after.getSubjectID()));
        assertThat(before.getCreated(), equalTo(after.getCreated()));
        assertThat(before.getMfaMethods(), equalTo(after.getMfaMethods()));
    }
}
