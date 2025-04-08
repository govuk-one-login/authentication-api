package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String UPDATED_TEST_EMAIL = "user.one@test.com";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String ALTERNATIVE_PHONE_NUMBER = "+447316763843";
    private static final LocalDateTime CREATED_DATE_TIME = LocalDateTime.now();
    private static final String TEST_MFA_APP_CREDENTIAL = "test-mfa-app-credential";
    private static final String ALTERNATIVE_TEST_MFA_APP_CREDENTIAL =
            "alternative-test-mfa-app-credential";

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());

    @Test
    void getOrGenerateSaltShouldReturnNewSaltWhenUserDoesNotHaveOne() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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

    @Test
    void shouldUpdateEmailAndDeletePreviousItems() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        dynamoService.updateEmail(TEST_EMAIL, UPDATED_TEST_EMAIL, CREATED_DATE_TIME);

        assertEmailHasBeenUpdated(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithAccountVerified() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
        dynamoService.setAccountVerified(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        dynamoService.updateEmail(TEST_EMAIL, UPDATED_TEST_EMAIL, CREATED_DATE_TIME);

        assertEmailHasBeenUpdated(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithSalt() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
        userStore.addSalt(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        dynamoService.updateEmail(TEST_EMAIL, UPDATED_TEST_EMAIL, CREATED_DATE_TIME);

        assertEmailHasBeenUpdated(userProfile, userCredentials);
    }

    @Test
    void shouldUpdateEmailAndDeletePreviousItemsWithMfaMethods() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());

        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, false, true, TEST_MFA_APP_CREDENTIAL);
        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();

        UserCredentials userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

        dynamoService.updateEmail(TEST_EMAIL, UPDATED_TEST_EMAIL, CREATED_DATE_TIME);

        assertEmailHasBeenUpdated(userProfile, userCredentials);
    }

    @Test
    void shouldAddAuthAppMFAMethod() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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

    @Nested
    class MfaMethodsSupportingMultipleTests {
        @BeforeEach
        void setup() {
            userStore.signUp(TEST_EMAIL, "password-1", new Subject());
        }

        private static MFAMethod defaultPrioritySmsData =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        "04615937-eb48-4a1f-9de2-2ff0a3dc3bc4");

        private static MFAMethod backupPrioritySmsData =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        PHONE_NUMBER,
                        PriorityIdentifier.BACKUP,
                        "daa4b59d-4efa-4e97-8b48-e6732c953060");

        private static MFAMethod defaultPriorityAuthAppData =
                MFAMethod.authAppMfaMethod(
                        TEST_MFA_APP_CREDENTIAL,
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        "7968d195-7db3-45f6-b7d3-a627aad118b7");

        private static MFAMethod backupAuthAppData =
                MFAMethod.authAppMfaMethod(
                        TEST_MFA_APP_CREDENTIAL,
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        "03a89933-cddd-471d-8fdb-562f14a2404f");

        @Test
        void shouldAddDefaultPriorityAuthAppMFAMethodWhenNoOtherMethodExists() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertSingleMfaMethodExistsWithData(userCredentials, defaultPriorityAuthAppData);
        }

        @Test
        void shouldAddDefaultPriortySmsMFAMethodWhenNoOtherDefaultExists() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertSingleMfaMethodExistsWithData(userCredentials, defaultPrioritySmsData);
        }

        @Test
        void aDefaultPriorityMfaMethodShouldReplaceAnExistingDefaultPriorityMethod() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);

            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertSingleMfaMethodExistsWithData(userCredentials, defaultPriorityAuthAppData);
        }

        @Test
        void aDefaultPriorityMfaMethodShouldReplaceAnExistingMethodWithoutPriority() {
            // Add auth app mfa using existing method which does not contain the new fields,
            // resulting in a null priority field
            dynamoService.updateMFAMethod(
                    TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, "some-credential");

            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertSingleMfaMethodExistsWithData(userCredentials, defaultPriorityAuthAppData);
        }

        @Test
        void anMfaMethodShouldNotReplaceAnExistingMethodOfADifferentTypeWithDifferentPriority() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);

            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupAuthAppData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupAuthAppData);
        }

        @Test
        void anMfaMethodShouldNotReplaceAnExistingMethodOfTheSameTypeWithDifferentPriority() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);

            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupPrioritySmsData);
        }

        @Test
        void shouldDeleteAnMfaMethodByIdentifier() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            dynamoService.deleteMfaMethodByIdentifier(
                    TEST_EMAIL, backupPrioritySmsData.getMfaIdentifier());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertSingleMfaMethodExistsWithData(userCredentials, defaultPrioritySmsData);
        }

        @Test
        void shouldNotDeleteAnyMfaMethodsIfNoneWithTheIdentifierExists() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            dynamoService.deleteMfaMethodByIdentifier(TEST_EMAIL, "some-other-identifier");

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupPrioritySmsData);
        }

        @Test
        void shouldUpdateAPhoneNumber() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedPhoneNumber = "111222333";

            var result =
                    dynamoService.updateMigratedMethodPhoneNumber(
                            TEST_EMAIL,
                            updatedPhoneNumber,
                            defaultPrioritySmsData.getMfaIdentifier());

            var expectedUpdatedDefaultSmsMethod =
                    MFAMethod.smsMfaMethod(
                            defaultPrioritySmsData.isMethodVerified(),
                            defaultPrioritySmsData.isEnabled(),
                            updatedPhoneNumber,
                            PriorityIdentifier.valueOf(defaultPrioritySmsData.getPriority()),
                            defaultPrioritySmsData.getMfaIdentifier());

            var returnedMethods = result.get();
            var updatedDefaultMethod =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.DEFAULT.name()))
                            .findFirst()
                            .get();
            var backupMethod =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertRetrievedMethodHasData(expectedUpdatedDefaultSmsMethod, updatedDefaultMethod);
            assertRetrievedMethodHasData(backupPrioritySmsData, backupMethod);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, expectedUpdatedDefaultSmsMethod, backupPrioritySmsData);
        }

        @Test
        void shouldUpdateAnAuthAppCredential() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedCredential = "some-updated-credential";

            var result =
                    dynamoService.updateMigratedAuthAppCredential(
                            TEST_EMAIL,
                            updatedCredential,
                            defaultPriorityAuthAppData.getMfaIdentifier());

            var expectedUpdatedAuthAppMethod =
                    MFAMethod.authAppMfaMethod(
                            updatedCredential,
                            defaultPriorityAuthAppData.isMethodVerified(),
                            defaultPriorityAuthAppData.isEnabled(),
                            PriorityIdentifier.valueOf(defaultPriorityAuthAppData.getPriority()),
                            defaultPriorityAuthAppData.getMfaIdentifier());

            var returnedMethods = result.get();
            var updatedDefaultPriorityMethod =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.DEFAULT.name()))
                            .findFirst()
                            .get();
            var returnedBackupMethod =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertRetrievedMethodHasData(
                    updatedDefaultPriorityMethod, expectedUpdatedAuthAppMethod);
            assertRetrievedMethodHasData(returnedBackupMethod, backupPrioritySmsData);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, expectedUpdatedAuthAppMethod, backupPrioritySmsData);
        }

        @Test
        void
                shouldReturnAnErrorAndDoNoUpdatesForUpdatePhoneNumberIfMfaMethodByIdentifierDoesNotExist() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedPhoneNumber = "111222333";

            var result =
                    dynamoService.updateMigratedMethodPhoneNumber(
                            TEST_EMAIL, updatedPhoneNumber, "some-other-identifier");

            assertEquals(
                    "Mfa method with identifier some-other-identifier does not exist",
                    result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupPrioritySmsData);
        }

        @Test
        void
                shouldReturnAnErrorAndDoNoUpdatesForUpdateAuthAppCredentialIfMfaMethodByIdentifierDoesNotExist() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedCredential = "some-updated-credential";

            var result =
                    dynamoService.updateMigratedAuthAppCredential(
                            TEST_EMAIL, updatedCredential, "some-other-identifier");

            assertEquals(
                    "Mfa method with identifier some-other-identifier does not exist",
                    result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPriorityAuthAppData, backupPrioritySmsData);
        }

        @Test
        void shouldReturnAnErrorAndDoNoUpdatesWhenCallingUpdatePhoneNumberIfMfaMethodIsNotSms() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPriorityAuthAppData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedPhoneNumber = "111222333";

            var result =
                    dynamoService.updateMigratedMethodPhoneNumber(
                            TEST_EMAIL,
                            updatedPhoneNumber,
                            defaultPriorityAuthAppData.getMfaIdentifier());

            assertEquals(
                    format(
                            "Attempted to update phone number for non sms method with identifier %s",
                            defaultPriorityAuthAppData.getMfaIdentifier()),
                    result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPriorityAuthAppData, backupPrioritySmsData);
        }

        @Test
        void shouldReturnAnErrorAndDoNoUpdatesWhenCallingUpdateAuthAppIfMfaMethodIsNotAuthApp() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var updatedCredential = "some-other-credential";

            var result =
                    dynamoService.updateMigratedAuthAppCredential(
                            TEST_EMAIL,
                            updatedCredential,
                            defaultPrioritySmsData.getMfaIdentifier());

            assertEquals(
                    format(
                            "Attempted to update auth app credential for non auth app method with identifier %s",
                            defaultPrioritySmsData.getMfaIdentifier()),
                    result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupPrioritySmsData);
        }

        @Test
        void shouldUpdateAllMfaMethodsForAUser() {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var promotedBackupMethod =
                    MFAMethod.smsMfaMethod(
                            backupPrioritySmsData.isMethodVerified(),
                            backupPrioritySmsData.isEnabled(),
                            backupPrioritySmsData.getDestination(),
                            PriorityIdentifier.DEFAULT,
                            backupPrioritySmsData.getMfaIdentifier());
            var demotedDefaultMethod =
                    MFAMethod.smsMfaMethod(
                            defaultPrioritySmsData.isMethodVerified(),
                            defaultPrioritySmsData.isEnabled(),
                            defaultPrioritySmsData.getDestination(),
                            PriorityIdentifier.BACKUP,
                            defaultPrioritySmsData.getMfaIdentifier());

            var result =
                    dynamoService.updateAllMfaMethodsForUser(
                            TEST_EMAIL, List.of(promotedBackupMethod, demotedDefaultMethod));

            var returnedMethods = result.get();
            var defaultMethodAfterUpdate =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.DEFAULT.name()))
                            .findFirst()
                            .get();
            var backupMethodAfterUpdate =
                    returnedMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertRetrievedMethodHasData(promotedBackupMethod, defaultMethodAfterUpdate);
            assertRetrievedMethodHasData(demotedDefaultMethod, backupMethodAfterUpdate);

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, promotedBackupMethod, demotedDefaultMethod);
        }

        private static Stream<Arguments> invalidMfaMethodsToExpectedErrorStrings() {
            return Stream.of(
                    Arguments.of(List.of(), "Mfa methods cannot be empty"),
                    Arguments.of(
                            List.of(defaultPriorityAuthAppData, backupAuthAppData),
                            "Cannot have two auth app mfa methods"),
                    Arguments.of(
                            List.of(defaultPriorityAuthAppData, defaultPrioritySmsData),
                            "Cannot have two mfa methods with the same priority"),
                    Arguments.of(
                            List.of(
                                    defaultPrioritySmsData,
                                    backupPrioritySmsData,
                                    backupAuthAppData),
                            "Cannot have more than two mfa methods"),
                    Arguments.of(
                            List.of(backupAuthAppData),
                            "Must have default priority mfa method defined"),
                    Arguments.of(
                            List.of(
                                    defaultPrioritySmsData,
                                    MFAMethod.smsMfaMethod(
                                            true,
                                            true,
                                            backupPrioritySmsData.getDestination(),
                                            PriorityIdentifier.BACKUP,
                                            defaultPrioritySmsData.getMfaIdentifier())),
                            "Cannot have mfa methods with the same identifier"));
        }

        @ParameterizedTest
        @MethodSource("invalidMfaMethodsToExpectedErrorStrings")
        void shouldReturnErrorAndNotUpdateMfaMethodsWhenUpdateIsInvalid(
                List<MFAMethod> invalidMethodCombination, String expectedErrorString) {
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, defaultPrioritySmsData);
            dynamoService.addMFAMethodSupportingMultiple(TEST_EMAIL, backupPrioritySmsData);

            var result =
                    dynamoService.updateAllMfaMethodsForUser(TEST_EMAIL, invalidMethodCombination);

            assertTrue(result.isLeft());
            assertEquals(expectedErrorString, result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);

            assertBackupAndDefaultMfaMethodsWithData(
                    userCredentials, defaultPrioritySmsData, backupPrioritySmsData);
        }

        @Test
        void shouldSetMfaIdentifierOnExistingMFAMethod() {
            dynamoService.updateMFAMethod(
                    TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);
            var identifier = "some-identifier";

            var result =
                    dynamoService.setMfaIdentifierForNonMigratedUserEnabledAuthApp(
                            TEST_EMAIL, identifier);

            assertTrue(result.isRight());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            var mfaMethods = userCredentials.getMfaMethods();

            assertEquals(1, mfaMethods.size());
            var mfaMethod = mfaMethods.get(0);

            assertEquals(identifier, mfaMethod.getMfaIdentifier());
            assertEquals(MFAMethodType.AUTH_APP.name(), mfaMethod.getMfaMethodType());
            assertTrue(mfaMethod.isMethodVerified());
            assertTrue(mfaMethod.isEnabled());
            assertEquals(TEST_MFA_APP_CREDENTIAL, mfaMethod.getCredentialValue());
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldReturnALeftWhenMFAMethodNotEnabledOrNotPresent(Boolean addDisabledMethod) {
            if (addDisabledMethod) {
                dynamoService.updateMFAMethod(
                        TEST_EMAIL, MFAMethodType.AUTH_APP, true, false, TEST_MFA_APP_CREDENTIAL);
            }

            var identifier = "some-identifier";

            var result =
                    dynamoService.setMfaIdentifierForNonMigratedUserEnabledAuthApp(
                            TEST_EMAIL, identifier);

            assertTrue(result.isLeft());
            assertEquals(
                    "Attempted to set mfa identifier for mfa method in user credentials but no enabled method found",
                    result.getLeft());

            var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
            var mfaMethods = userCredentials.getMfaMethods();

            if (addDisabledMethod) {
                assertEquals(1, mfaMethods.size());
                var mfaMethod = mfaMethods.get(0);

                assertNull(mfaMethod.getMfaIdentifier());
            }
        }

        private MFAMethod findMethodWithPriority(
                String priority, List<MFAMethod> retrievedMethods) {
            Predicate<MFAMethod> findCondition =
                    (MFAMethod method) -> Objects.equals(method.getPriority(), priority);
            return retrievedMethods.stream().filter(findCondition).findFirst().get();
        }

        private void assertBackupAndDefaultMfaMethodsWithData(
                UserCredentials userCredentials,
                MFAMethod expectedDefault,
                MFAMethod expectedBackup) {
            assertThat(userCredentials.getMfaMethods().size(), equalTo(2));
            var backupMethod = findMethodWithPriority("BACKUP", userCredentials.getMfaMethods());
            var defaultMethod = findMethodWithPriority("DEFAULT", userCredentials.getMfaMethods());
            assertRetrievedMethodHasData(backupMethod, expectedBackup);
            assertRetrievedMethodHasData(defaultMethod, expectedDefault);
        }

        private void assertRetrievedMethodHasData(
                MFAMethod retrievedMethod, MFAMethod expectedData) {
            assertThat(
                    retrievedMethod.isMethodVerified(), equalTo(expectedData.isMethodVerified()));
            assertThat(retrievedMethod.isEnabled(), equalTo(expectedData.isEnabled()));
            assertThat(retrievedMethod.getPriority(), equalTo(expectedData.getPriority()));
            assertThat(
                    retrievedMethod.getMfaIdentifier(), equalTo(expectedData.getMfaIdentifier()));
            if (expectedData.getMfaMethodType().equals(MFAMethodType.SMS.getValue())) {
                assertThat(
                        retrievedMethod.getMfaMethodType(), equalTo(MFAMethodType.SMS.getValue()));
                assertThat(retrievedMethod.getCredentialValue(), equalTo(null));
                assertThat(
                        retrievedMethod.getDestination(), equalTo(expectedData.getDestination()));
            } else {
                assertThat(
                        retrievedMethod.getMfaMethodType(),
                        equalTo(MFAMethodType.AUTH_APP.getValue()));
                assertThat(
                        retrievedMethod.getCredentialValue(),
                        equalTo(expectedData.getCredentialValue()));
                assertThat(retrievedMethod.getDestination(), equalTo(null));
            }
        }

        private void assertSingleMfaMethodExistsWithData(
                UserCredentials userCredentials, MFAMethod expectedData) {
            assertThat(userCredentials.getMfaMethods().size(), equalTo(1));
            assertRetrievedMethodHasData(userCredentials.getMfaMethods().get(0), expectedData);
        }
    }

    @Test
    void
            shouldSetAuthAppMFAMethodNotEnabledAndSetPhoneNumberAndAccountVerifiedWhenMfaMethodExists() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());

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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
    void mfaMethodShouldNotContainNewFieldsWhenSetByOldMethod() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());

        dynamoService.updateMFAMethod(
                TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, TEST_MFA_APP_CREDENTIAL);

        var updatedUserCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var mfaMethod = updatedUserCredentials.getMfaMethods().get(0);
        assertThat(mfaMethod.getMfaMethodType(), equalTo(MFAMethodType.AUTH_APP.getValue()));
        assertThat(mfaMethod.getCredentialValue(), equalTo(TEST_MFA_APP_CREDENTIAL));
        assertNull(mfaMethod.getDestination());
        assertNull(mfaMethod.getMfaIdentifier());
    }

    @Test
    void shouldSetVerifiedPhoneNumberAndReplaceExistingPhoneNumber() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
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
    void shouldRetrieveUserProfileFromSubject() {
        userStore.signUp("email1", "password-1", new Subject("1111"));

        assertThat(dynamoService.getUserProfileFromSubject("1111").getEmail(), equalTo("email1"));
    }

    @Test
    void shouldThrowErrorIfNoUserProfileExists() {
        assertThrows(
                RuntimeException.class,
                () -> dynamoService.getUserProfileFromSubject("NonExistentUser"),
                "No userCredentials found with query search");
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

    private void assertEmailHasBeenUpdated(
            UserProfile userProfile, UserCredentials userCredentials) {
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
