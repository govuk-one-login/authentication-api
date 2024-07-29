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
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;

class DynamoServiceIntegrationTest {

    private static final String ALTERNATIVE_PHONE_NUMBER = "+447316763843";
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

    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());

    @Test
    void getOrGenerateSaltShouldReturnNewSaltWhenUserDoesNotHaveOne() {
        setUpDynamo();
        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt.length, equalTo(32));
        assertThat(SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray(), equalTo(salt));
        UserProfile savedProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        assertThat(SdkBytes.fromByteBuffer(savedProfile.getSalt()).asByteArray(), equalTo(salt));
    }

    @Test
    void getOrGenerateSaltShouldReturnExistingSaltWhenOneExists() {
        setUpDynamo();
        byte[] existingSalt = userStore.addSalt(EMAIL);

        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt, equalTo(existingSalt));
        UserProfile savedProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        assertThat(
                existingSalt,
                equalTo(SdkBytes.fromByteBuffer(savedProfile.getSalt()).asByteArray()));
    }

    private void setUpDynamo() {
        userStore.signUp(EMAIL, PASSWORD, new Subject());
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItems() {
        setUpDynamo();

        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithAccountVerified() {
        setUpDynamo();
        dynamoService.setAccountVerified(EMAIL);

        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithSalt() {
        setUpDynamo();
        userStore.addSalt(EMAIL);

        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithMfaMethods() {
        setUpDynamo();

        dynamoService.updateMFAMethod(
                EMAIL, MFAMethodType.AUTH_APP, false, true, TEST_MFA_APP_CREDENTIAL);
        UserProfile userProfile = dynamoService.getUserProfileByEmailMaybe(EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);

        testUpdateEmail(userProfile, userCredentials);
    }

    @Test
    void shouldAddAuthAppMFAMethod() {
        setUpDynamo();
        dynamoService.updateMFAMethod(
                EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        UserCredentials updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);

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
                EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                EMAIL, "+4407316763843", true, true);
        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);

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
                EMAIL, UK_MOBILE_NUMBER, true, true);
        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserUserProfile = dynamoService.getUserProfileByEmail(EMAIL);

        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(null));
        assertThat(updatedUserUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserUserProfile.getPhoneNumber(), equalTo("+447316763843"));
        assertThat(updatedUserUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetAccountAndAuthVerifiedToTrue() {
        setUpDynamo();

        dynamoService.setAuthAppAndAccountVerified(EMAIL, TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);

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
        dynamoService.setAccountVerified(EMAIL);
        dynamoService.updateMFAMethod(
                EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);

        dynamoService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(EMAIL, "+447316763843");

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);
        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(emptyList()));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo("+447316763843"));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetVerifiedPhoneNumberAndReplaceExistingPhoneNumber() {
        setUpDynamo();
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                EMAIL, ALTERNATIVE_PHONE_NUMBER, true, true);

        dynamoService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(EMAIL, UK_MOBILE_NUMBER);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);
        assertThat(updatedUserCredentials.getMfaMethods(), equalTo(null));
        assertThat(updatedUserProfile.getAccountVerified(), equalTo(1));
        assertThat(updatedUserProfile.getPhoneNumber(), equalTo(UK_MOBILE_NUMBER));
        assertThat(updatedUserProfile.isPhoneNumberVerified(), equalTo(true));
    }

    @Test
    void shouldSetVerifiedAuthAppAndRemovePhoneNumberWhenPresent() {
        setUpDynamo();
        dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                EMAIL, ALTERNATIVE_PHONE_NUMBER, true, true);

        dynamoService.setVerifiedAuthAppAndRemoveExistingMfaMethod(EMAIL, TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);
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
                EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
        dynamoService.setAccountVerified(EMAIL);

        dynamoService.setVerifiedAuthAppAndRemoveExistingMfaMethod(
                EMAIL, ALTERNATIVE_TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var updatedUserProfile = dynamoService.getUserProfileByEmail(EMAIL);
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
        String[] suffixes = {"1111", "2222", "3333", "4444", "5555"};
        setupDynamoWithMultipleUsers(suffixes);

        for (String suffix : suffixes) {
            assertThat(
                    dynamoService.getOptionalUserProfileFromSubject(suffix).get().getEmail(),
                    equalTo("email" + suffix));
        }
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
        setupDynamoWithMultipleUsers(new String[] {"1111", "2222", "3333", "4444", "5555"});
    }

    private void setupDynamoWithMultipleUsers(String[] suffixes) {
        for (String suffix : suffixes) {
            userStore.signUp("email" + suffix, PASSWORD, new Subject(suffix));
        }
    }

    private void setupDynamoWithMultipleUsersWithDifferentTermsAndConditions() {
        userStore.signUp("email0", PASSWORD, new Subject("0000"), "1.0");
        userStore.signUp("email1", PASSWORD, new Subject("1111"), "1.0");
        userStore.signUp("email2", PASSWORD, new Subject("2222"), "1.0");
        userStore.signUp("email3", PASSWORD, new Subject("3333"), "1.1");
        userStore.signUp("email4", PASSWORD, new Subject("4444"), "1.1");
        userStore.signUp("email5", PASSWORD, new Subject("5555"), "1.2");
        userStore.signUp("email6", PASSWORD, new Subject("6666"), "1.2");
        userStore.signUp("email7", PASSWORD, new Subject("7777"), "1.2");
        userStore.signUp("email8", PASSWORD, new Subject("8888"), "1.3");
        userStore.signUp("email9", PASSWORD, new Subject("9999"), "1.3");
        userStore.signUp("email10", PASSWORD, new Subject("A0000"), null);
        userStore.signUp("email11", PASSWORD, new Subject("A1111"), null);
        userStore.addUnverifiedUser("email12", PASSWORD, new Subject("A2222"), "1.3");
        userStore.addUnverifiedUser("email13", PASSWORD, new Subject("A3333"), "1.3");
        userStore.addUnverifiedUser("email14", PASSWORD, new Subject("A4444"), "1.3");
    }

    private void testUpdateEmail(UserProfile userProfile, UserCredentials userCredentials) {
        dynamoService.updateEmail(EMAIL, EMAIL_NEW, CREATED_DATE_TIME);

        UserProfile updatedUserProfile =
                dynamoService.getUserProfileByEmailMaybe(EMAIL_NEW).orElseThrow();

        UserCredentials updatedUserCredentials =
                dynamoService.getUserCredentialsFromEmail(EMAIL_NEW);

        assertThat(updatedUserProfile.getEmail(), equalTo(EMAIL_NEW));
        assertThat(updatedUserCredentials.getEmail(), equalTo(EMAIL_NEW));

        assertThat(updatedUserProfile.getUpdated(), equalTo(CREATED_DATE_TIME.toString()));
        assertThat(updatedUserCredentials.getUpdated(), equalTo(CREATED_DATE_TIME.toString()));

        compareUserProfiles(userProfile, updatedUserProfile);
        compareUserCredentials(userCredentials, updatedUserCredentials);

        assertThat(dynamoService.getUserProfileByEmail(EMAIL), equalTo(null));
        assertThat(dynamoService.getUserCredentialsFromEmail(EMAIL), equalTo(null));
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
