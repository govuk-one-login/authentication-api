package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class DynamoServiceIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String UPDATED_TEST_EMAIL = "user.one@test.com";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String ALTERNATIVE_PHONE_NUMBER = "+447316763843";
    private static final String CLIENT_ID = "client-id";
    private static final LocalDateTime CREATED_DATE_TIME = LocalDateTime.now();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final Set<String> CLAIMS =
            ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());

    private static final String TEST_MFA_APP_CREDENTIAL = "test-mfa-app-credential";
    private static final String ALTERNATIVE_TEST_MFA_APP_CREDENTIAL =
            "alternative-test-mfa-app-credential";

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    DynamoService dynamoService = new DynamoService(TEST_CONFIGURATION_SERVICE);

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
    void shouldUpdateEmailAndDeletePreviousItemsWithSalt() {
        setUpDynamo();
        userStore.addSalt(TEST_EMAIL);

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
    void
            shouldSetAuthAppMFAMethodNotEnabledAndSetPhoneNumberAndAccountVerifiedWhenMfaMethodExists() {
        setUpDynamo();
        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                TEST_EMAIL, "+4407316763843", true, true);
        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        MFAMethod mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(false));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo("+447316763843"));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetSetPhoneNumberAndAccountVerifiedWhenMfaMethodDoesNotExists() {
        setUpDynamo();
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                TEST_EMAIL, "+4407316763843", true, true);
        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(null));
        assertThat(updatedUserUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserUserProfile.getPhoneNumber(), equalTo("+447316763843"));
        assertThat(updatedUserUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetAccountAndAuthVerifiedToTrue() {
        setUpDynamo();

        dynamoService.setAuthAppAndAccountVerified(TEST_EMAIL, TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods().size(), equalTo(1));
        var mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.isMethodVerified(), equalTo(true));
        assertThat(mfaMethod.isEnabled(), equalTo(true));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
    }

    @Test
    void shouldSetVerifiedPhoneNumberAndRemoveAuthAppWhenPresent() {
        setUpDynamo();
        dynamoService.setAccountVerified(TEST_EMAIL);
        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);

        dynamoService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(TEST_EMAIL, "+447316763843");

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(emptyList()));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo("+447316763843"));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetVerifiedPhoneNumberAndReplaceExistingPhoneNumber() {
        setUpDynamo();
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                TEST_EMAIL, ALTERNATIVE_PHONE_NUMBER, true, true);

        dynamoService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(TEST_EMAIL, PHONE_NUMBER);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(null));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetVerifiedAuthAppAndRemovePhoneNumberWhenPresent() {
        setUpDynamo();
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                TEST_EMAIL, ALTERNATIVE_PHONE_NUMBER, true, true);

        dynamoService.setVerifiedAuthAppAndRemoveExistingMfaMethod(
                TEST_EMAIL, TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        List<MFAMethod> mfaMethods = updatedUserCredentials.getMfaMethods();
        assertThat(mfaMethods.size(), equalTo(1));
        assertThat(mfaMethods.get(0).isMethodVerified(), equalTo(true));
        assertThat(mfaMethods.get(0).isEnabled(), equalTo(true));
        assertThat(mfaMethods.get(0).getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo(null));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(false));
    }

    @Test
    void shouldSetVerifiedAuthAppAndRemoveExistingAuthAppWhenPresent() {
        setUpDynamo();
        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.setAccountVerified(TEST_EMAIL);

        dynamoService.setVerifiedAuthAppAndRemoveExistingMfaMethod(
                TEST_EMAIL, ALTERNATIVE_TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        List<MFAMethod> mfaMethods = updatedUserCredentials.getMfaMethods();
        assertThat(mfaMethods.size(), equalTo(1));
        assertThat(mfaMethods.get(0).isMethodVerified(), equalTo(true));
        assertThat(mfaMethods.get(0).isEnabled(), equalTo(true));
        assertThat(
                mfaMethods.get(0).getCredentialValue(),
                equalTo(ALTERNATIVE_TEST_MFA_APP_CREDENTIAL));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo(null));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(false));
    }

    @Test
    void shouldRetrieveUserProfileBySubjectId() {
        setupDynamoWithMultipleUsers();

        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("1111").get().getEmail(),
                equalTo("email1"));
        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("2222").get().getEmail(),
                equalTo("email2"));
        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("3333").get().getEmail(),
                equalTo("email3"));
        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("4444").get().getEmail(),
                equalTo("email4"));
        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("5555").get().getEmail(),
                equalTo("email5"));
    }

    @Test
    void shouldGetUsersOnTermsAndConditionsVersion() {
        setupDynamoWithMultipleUsers();

        var users =
                dynamoService.getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                        null, List.of("1.0"));
        assertThat(users.count(), equalTo(5L));
    }

    @Test
    void shouldGetVerifiedUsersOnTermsAndConditionsVariousVersions() {
        setupDynamoWithMultipleUsersWithDifferentTermsAndConditions();

        assertThat(
                dynamoService
                        .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                                null, List.of("1.0"))
                        .count(),
                equalTo(3L));
        assertThat(
                dynamoService
                        .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                                null, List.of("1.1"))
                        .count(),
                equalTo(2L));
        assertThat(
                dynamoService
                        .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                                null, List.of("1.2"))
                        .count(),
                equalTo(3L));
        assertThat(
                dynamoService
                        .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                                null, List.of("1.3"))
                        .count(),
                equalTo(2L));

        assertThat(
                dynamoService
                        .getBulkUserEmailAudienceStreamOnTermsAndConditionsVersion(
                                null, List.of("1.3", "1.1"))
                        .count(),
                equalTo(4L));
    }

    @Test
    void shouldThrowWhenUserNotFoundBySubjectId() {
        setupDynamoWithMultipleUsers();

        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("7777"), equalTo(Optional.empty()));
        assertThat(
                dynamoService.getOptionalUserProfileFromSubject("8888"), equalTo(Optional.empty()));
    }

    private void setupDynamoWithMultipleUsers() {
        userStore.signUp("email1", "password-1", new Subject("1111"));
        userStore.signUp("email2", "password-1", new Subject("2222"));
        userStore.signUp("email3", "password-1", new Subject("3333"));
        userStore.signUp("email4", "password-1", new Subject("4444"));
        userStore.signUp("email5", "password-1", new Subject("5555"));
    }

    private void setupDynamoWithMultipleUsersWithDifferentTermsAndConditions() {
        userStore.signUp("email0", "password-1", new Subject("0000"), "1.0");
        userStore.signUp("email1", "password-1", new Subject("1111"), "1.0");
        userStore.signUp("email2", "password-1", new Subject("2222"), "1.0");
        userStore.signUp("email3", "password-1", new Subject("3333"), "1.1");
        userStore.signUp("email4", "password-1", new Subject("4444"), "1.1");
        userStore.signUp("email5", "password-1", new Subject("5555"), "1.2");
        userStore.signUp("email6", "password-1", new Subject("6666"), "1.2");
        userStore.signUp("email7", "password-1", new Subject("7777"), "1.2");
        userStore.signUp("email8", "password-1", new Subject("8888"), "1.3");
        userStore.signUp("email9", "password-1", new Subject("9999"), "1.3");
        userStore.signUp("email10", "password-1", new Subject("A0000"), null);
        userStore.signUp("email11", "password-1", new Subject("A1111"), null);
        userStore.addUnverifiedUser("email12", "password-1", new Subject("A2222"), "1.3");
        userStore.addUnverifiedUser("email13", "password-1", new Subject("A3333"), "1.3");
        userStore.addUnverifiedUser("email14", "password-1", new Subject("A4444"), "1.3");
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
