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
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MFAMethodsServiceIntegrationTest {

    private static final String EMAIL = "joe.bloggs@example.com";
    private static final String PHONE_NUMBER_WITHOUT_COUNTRY_CODE = "07900000000";
    private static final String PHONE_NUMBER_WITH_COUNTRY_CODE = "+447900000000";
    private static final String PHONE_NUMBER_TWO_WITHOUT_COUNTRY_CODE = "07900000100";
    private static final String PHONE_NUMBER_TWO_WITH_COUNTRY_CODE = "+447900000100";
    private static final String AUTH_APP_CREDENTIAL = "some-credential";
    private static final String SMS_MFA_IDENTIFIER_1 = "ea83592f-b9bf-436f-b4f4-ee33f610ee05";
    private static final String SMS_MFA_IDENTIFIER_2 = "3634a5e3-dac8-4804-8d40-181722b48ae1";
    private static final String APP_MFA_IDENTIFIER_1 = "a87e57e5-6175-4be7-af7d-547a390b36c1";
    private static final String APP_MFA_IDENTIFIER_2 = "898a7e13-c354-430a-a3ca-8cc6c6391057";
    private static final MFAMethod defaultPriorityAuthApp =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL,
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    APP_MFA_IDENTIFIER_1);
    private static final String AUTH_APP_CREDENTIAL_TWO = "another-credential";
    private static final MFAMethod backupPriorityAuthApp =
            MFAMethod.authAppMfaMethod(
                    AUTH_APP_CREDENTIAL_TWO,
                    true,
                    true,
                    PriorityIdentifier.BACKUP,
                    APP_MFA_IDENTIFIER_2);
    private static final MFAMethod defaultPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    PHONE_NUMBER_WITH_COUNTRY_CODE,
                    PriorityIdentifier.DEFAULT,
                    SMS_MFA_IDENTIFIER_1);
    private static final MFAMethod backupPrioritySms =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    PHONE_NUMBER_TWO_WITH_COUNTRY_CODE,
                    PriorityIdentifier.BACKUP,
                    SMS_MFA_IDENTIFIER_2);
    MFAMethodsService mfaMethodsService = new MFAMethodsService(ConfigurationService.getInstance());
    private UserProfile userProfile;

    @RegisterExtension static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @Nested
    class RetrieveWhenAUserIsNotMigrated {

        private static final String EXPLICITLY_NON_MIGRATED_USER_EMAIL = "not-migrated@example.com";

        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
            userStoreExtension.signUp(
                    EXPLICITLY_NON_MIGRATED_USER_EMAIL, "password-1", new Subject());
            userStoreExtension.setMfaMethodsMigrated(EXPLICITLY_NON_MIGRATED_USER_EMAIL, false);
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnSingleSmsMethodWhenVerified(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER_WITH_COUNTRY_CODE);
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.setPhoneNumberMfaIdentifer(email, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var expectedData =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            PHONE_NUMBER_WITH_COUNTRY_CODE,
                            PriorityIdentifier.DEFAULT,
                            mfaIdentifier);
            assertEquals(List.of(expectedData), result);
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldStoreAnMfaIdentifierForANonMigratedSmsMethodOnRead(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER_WITH_COUNTRY_CODE);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            userProfile = userStoreExtension.getUserProfileFromEmail(email).get();
            var mfaIdentifier = userProfile.getMfaIdentifier();
            assertFalse(mfaIdentifier.isEmpty());

            var expectedData =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            PHONE_NUMBER_WITH_COUNTRY_CODE,
                            PriorityIdentifier.DEFAULT,
                            mfaIdentifier);
            assertEquals(List.of(expectedData), result);
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnSingleAuthAppMethodWhenEnabled(String email) {
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.addAuthAppMethodWithIdentifier(
                    email, true, true, AUTH_APP_CREDENTIAL, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var expectedAuthApp =
                    MFAMethod.authAppMfaMethod(
                            AUTH_APP_CREDENTIAL,
                            true,
                            true,
                            PriorityIdentifier.DEFAULT,
                            mfaIdentifier);

            assertEquals(1, result.size());
            assertTrue(mfaMethodsAreEqualIgnoringUpdated(expectedAuthApp, result.get(0)));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldStoreAnMfaIdentifierForANonMigratedAuthAppOnRead(String email) {
            userStoreExtension.addAuthAppMethod(email, true, true, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var retrievedMethodsFromDatabase = userStoreExtension.getMfaMethod(email);
            assertEquals(1, retrievedMethodsFromDatabase.size());

            var retrievedAuthApp = retrievedMethodsFromDatabase.get(0);
            assertEquals(MFAMethodType.AUTH_APP.getValue(), retrievedAuthApp.getMfaMethodType());
            assertNotNull(retrievedAuthApp.getMfaIdentifier());

            var mfaIdentifier = retrievedAuthApp.getMfaIdentifier();

            var expectedAuthAppMfa =
                    MFAMethod.authAppMfaMethod(
                            AUTH_APP_CREDENTIAL,
                            true,
                            true,
                            PriorityIdentifier.DEFAULT,
                            mfaIdentifier);
            assertEquals(1, result.size());
            assertTrue(mfaMethodsAreEqualIgnoringUpdated(expectedAuthAppMfa, result.get(0)));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void authAppShouldTakePrecedenceOverSmsMethodForNonMigratedUser(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER_WITH_COUNTRY_CODE);
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.addAuthAppMethodWithIdentifier(
                    email, true, true, AUTH_APP_CREDENTIAL, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var expectedData =
                    MFAMethod.authAppMfaMethod(
                            AUTH_APP_CREDENTIAL,
                            true,
                            true,
                            PriorityIdentifier.DEFAULT,
                            mfaIdentifier);
            assertEquals(1, result.size());
            assertTrue(mfaMethodsAreEqualIgnoringUpdated(expectedData, result.get(0)));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenAuthAppMethodNotEnabled(String email) {
            userStoreExtension.addAuthAppMethod(email, true, false, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            assertEquals(result, List.of());
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenAuthAppMethodNotVerified(String email) {
            userStoreExtension.addAuthAppMethod(email, false, true, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            assertEquals(List.of(), result);
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenSmsMethodNotVerified(String email) {
            userStoreExtension.setPhoneNumberAndVerificationStatus(
                    email, PHONE_NUMBER_WITH_COUNTRY_CODE, false, true);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            assertEquals(result, List.of());
        }

        @Nested
        class WhenMigratingAUser {
            @ParameterizedTest
            @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
            void shouldMigrateActiveSmsNeedingMigration(String email) {
                // Arrange
                userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER_WITH_COUNTRY_CODE);

                var credentialsMfaMethodsBefore =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertNull(credentialsMfaMethodsBefore);

                UserProfile userProfileBefore =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertFalse(userProfileBefore.getMfaMethodsMigrated());
                assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, userProfileBefore.getPhoneNumber());
                assertTrue(userProfileBefore.isPhoneNumberVerified());

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(email);

                // Assert
                assertTrue(mfaMigrationFailureReason.isEmpty());

                var credentialsMfaMethodsAfter =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertEquals(1, credentialsMfaMethodsAfter.size());

                var credentialSmsMfaMethod = credentialsMfaMethodsAfter.get(0);
                assertTrue(credentialSmsMfaMethod.isMethodVerified());
                assertTrue(credentialSmsMfaMethod.isEnabled());
                assertEquals(
                        PHONE_NUMBER_WITH_COUNTRY_CODE, credentialSmsMfaMethod.getDestination());
                assertEquals(
                        PriorityIdentifier.DEFAULT.toString(),
                        credentialSmsMfaMethod.getPriority());
                assertNotNull(credentialSmsMfaMethod.getMfaIdentifier());

                UserProfile userProfileAfter =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertTrue(userProfileAfter.getMfaMethodsMigrated());
                assertNull(userProfileAfter.getPhoneNumber());
                assertFalse(userProfileAfter.isPhoneNumberVerified());
                assertNull(userProfileAfter.getMfaIdentifier());
            }

            @ParameterizedTest
            @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
            void shouldMigrateActiveSmsWithExistingMfaIdentifierNeedingMigration(String email) {
                // Arrange
                userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER_WITH_COUNTRY_CODE);
                var existingIdentifier = UUID.randomUUID().toString();
                userStoreExtension.setPhoneNumberMfaIdentifer(email, existingIdentifier);

                var credentialsMfaMethodsBefore =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertNull(credentialsMfaMethodsBefore);

                UserProfile userProfileBefore =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertFalse(userProfileBefore.getMfaMethodsMigrated());
                assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, userProfileBefore.getPhoneNumber());
                assertTrue(userProfileBefore.isPhoneNumberVerified());

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(email);

                // Assert
                assertTrue(mfaMigrationFailureReason.isEmpty());

                var credentialsMfaMethodsAfter =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertEquals(1, credentialsMfaMethodsAfter.size());

                var credentialSmsMfaMethod = credentialsMfaMethodsAfter.get(0);
                assertTrue(credentialSmsMfaMethod.isMethodVerified());
                assertTrue(credentialSmsMfaMethod.isEnabled());
                assertEquals(
                        PHONE_NUMBER_WITH_COUNTRY_CODE, credentialSmsMfaMethod.getDestination());
                assertEquals(
                        PriorityIdentifier.DEFAULT.toString(),
                        credentialSmsMfaMethod.getPriority());
                assertEquals(credentialSmsMfaMethod.getMfaIdentifier(), existingIdentifier);

                UserProfile userProfileAfter =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertTrue(userProfileAfter.getMfaMethodsMigrated());
                assertNull(userProfileAfter.getPhoneNumber());
                assertFalse(userProfileAfter.isPhoneNumberVerified());
                assertNull(userProfileAfter.getMfaIdentifier());
            }

            @ParameterizedTest
            @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
            void shouldMarkUserAsMigratedAndMigrateAuthAppIfAuthAppAlreadyExistsOnCredential(
                    String email) {
                // Arrange
                userStoreExtension.addAuthAppMethod(email, true, true, AUTH_APP_CREDENTIAL);

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(email);

                // Assert
                assertTrue(mfaMigrationFailureReason.isEmpty());

                var credentialsMfaMethods =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertEquals(1, credentialsMfaMethods.size());
                var credentialAuthAppMfaMethod = credentialsMfaMethods.get(0);
                assertEquals(AUTH_APP_CREDENTIAL, credentialAuthAppMfaMethod.getCredentialValue());
                assertTrue(credentialAuthAppMfaMethod.isMethodVerified());
                assertTrue(credentialAuthAppMfaMethod.isEnabled());
                assertEquals(
                        PriorityIdentifier.DEFAULT.toString(),
                        credentialAuthAppMfaMethod.getPriority());
                assertNotNull(credentialAuthAppMfaMethod.getMfaIdentifier());

                var isMigrated =
                        userStoreExtension
                                .getUserProfileFromEmail(email)
                                .get()
                                .getMfaMethodsMigrated();
                assertTrue(isMigrated);
            }

            @ParameterizedTest
            @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
            void
                    shouldMarkUserAsMigratedAndMigrateAuthAppWithExistingMfaIdentifierIfAuthAppAlreadyExistsOnCredential(
                            String email) {
                // Arrange
                var existingIdentifier = UUID.randomUUID().toString();
                userStoreExtension.addAuthAppMethodWithIdentifier(
                        email, true, true, AUTH_APP_CREDENTIAL, existingIdentifier);

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(email);

                // Assert
                assertTrue(mfaMigrationFailureReason.isEmpty());

                var credentialsMfaMethods =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertEquals(1, credentialsMfaMethods.size());
                var credentialAuthAppMfaMethod = credentialsMfaMethods.get(0);
                assertEquals(AUTH_APP_CREDENTIAL, credentialAuthAppMfaMethod.getCredentialValue());
                assertTrue(credentialAuthAppMfaMethod.isMethodVerified());
                assertTrue(credentialAuthAppMfaMethod.isEnabled());
                assertEquals(
                        PriorityIdentifier.DEFAULT.toString(),
                        credentialAuthAppMfaMethod.getPriority());
                assertEquals(existingIdentifier, credentialAuthAppMfaMethod.getMfaIdentifier());

                var isMigrated =
                        userStoreExtension
                                .getUserProfileFromEmail(email)
                                .get()
                                .getMfaMethodsMigrated();
                assertTrue(isMigrated);
            }

            @Test
            void shouldErrorIfUserProfileNotFound() {
                // Arrange
                userStoreExtension.addVerifiedPhoneNumber(EMAIL, PHONE_NUMBER_WITH_COUNTRY_CODE);

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(
                                "non-existent-email@example.com");

                // Assert
                assertEquals(
                        MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL,
                        mfaMigrationFailureReason.get());
            }
        }
    }

    @Nested
    class RetrieveWhenAUserIsMigrated {
        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
        }

        @Test
        void shouldReturnSingleSmsMethodRegardlessOfNumberInUserProfile() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);

            // Adds a number to the user profile table. Users should not be able to get into a state
            // where they have a verified number here and a different number in user credentials,
            // but regardless for a migrated user we will ignore this entry
            userStoreExtension.addVerifiedPhoneNumber(EMAIL, "+44987654321");

            var result = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(List.of(defaultPrioritySms), result);
        }

        @Test
        void shouldReturnSingleAuthAppMethodWhenEnabled() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var result = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(List.of(defaultPriorityAuthApp), result);
        }

        private static Stream<List<MFAMethod>> mfaMethodsCombinations() {
            return Stream.of(
                    List.of(defaultPriorityAuthApp, backupPriorityAuthApp),
                    List.of(defaultPrioritySms, backupPrioritySms),
                    List.of(defaultPriorityAuthApp, backupPrioritySms),
                    List.of(defaultPrioritySms, backupPriorityAuthApp));
        }

        @ParameterizedTest
        @MethodSource("mfaMethodsCombinations")
        void shouldReturnMultipleMethodsWhenTheyExist(List<MFAMethod> mfaMethods) {
            mfaMethods.forEach(
                    mfaMethod ->
                            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, mfaMethod));

            var result = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(mfaMethods, result);
        }
    }

    @Nested
    class AddBackupMfaTests {
        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
        }

        @Test
        void authAppUserShouldSuccessfullyAddSmsMfaInPost() {
            userStoreExtension.addMfaMethodSupportingMultiple(
                    MFAMethodsServiceIntegrationTest.EMAIL, defaultPriorityAuthApp);
            RequestSmsMfaDetail requestSmsMfaDetail =
                    new RequestSmsMfaDetail(PHONE_NUMBER_WITH_COUNTRY_CODE, "123456");

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, requestSmsMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MFAMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .getSuccess();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MFAMethodsServiceIntegrationTest.EMAIL);
            var storedBackupMethod =
                    mfaMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();

            assertEquals(MFAMethodType.SMS.getValue(), storedBackupMethod.getMfaMethodType());
            assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, storedBackupMethod.getDestination());

            assertEquals(storedBackupMethod.getMfaIdentifier(), result.getMfaIdentifier());
            assertDoesNotThrow(() -> UUID.fromString(result.getMfaIdentifier()));
            assertEquals(PriorityIdentifier.BACKUP.name(), result.getPriority());
            assertTrue(result.isMethodVerified());
            assertEquals(MFAMethodType.SMS.getValue(), result.getMfaMethodType());
            assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, result.getDestination());
        }

        @Test
        void
                aPhoneNumberWithoutACountryCodeShouldBeStoredAndReturnedWithTheDefaultCountryCodeForBackupMfa() {
            userStoreExtension.addMfaMethodSupportingMultiple(
                    MFAMethodsServiceIntegrationTest.EMAIL, defaultPriorityAuthApp);
            RequestSmsMfaDetail requestSmsMfaDetail =
                    new RequestSmsMfaDetail(PHONE_NUMBER_WITHOUT_COUNTRY_CODE, "123456");

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, requestSmsMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MFAMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .getSuccess();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MFAMethodsServiceIntegrationTest.EMAIL);
            var storedBackupMethod =
                    mfaMethods.stream()
                            .filter(m -> m.getPriority().equals(PriorityIdentifier.BACKUP.name()))
                            .findFirst()
                            .get();
            assertEquals(MFAMethodType.SMS.getValue(), storedBackupMethod.getMfaMethodType());
            assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, storedBackupMethod.getDestination());

            assertEquals(storedBackupMethod.getMfaIdentifier(), result.getMfaIdentifier());
            assertDoesNotThrow(() -> UUID.fromString(result.getMfaIdentifier()));
            assertEquals(PriorityIdentifier.BACKUP.name(), result.getPriority());
            assertTrue(result.isMethodVerified());
            assertEquals(MFAMethodType.SMS.getValue(), result.getMfaMethodType());
            assertEquals(PHONE_NUMBER_WITH_COUNTRY_CODE, result.getDestination());
        }

        @Test
        void smsUserShouldSuccessfullyAddAuthAppMfa() {
            userStoreExtension.addMfaMethodSupportingMultiple(
                    MFAMethodsServiceIntegrationTest.EMAIL, defaultPrioritySms);

            RequestAuthAppMfaDetail requestAuthAppMfaDetail =
                    new RequestAuthAppMfaDetail(AUTH_APP_CREDENTIAL);

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, requestAuthAppMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MFAMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .getSuccess();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MFAMethodsServiceIntegrationTest.EMAIL);
            boolean authAppMethodExists =
                    mfaMethods.stream()
                            .anyMatch(
                                    method ->
                                            method.getMfaMethodType()
                                                    .equals(MFAMethodType.AUTH_APP.getValue()));

            assertTrue(authAppMethodExists);
            assertDoesNotThrow(() -> UUID.fromString(result.getMfaIdentifier()));
            assertEquals(PriorityIdentifier.BACKUP.name(), result.getPriority());
            assertTrue(result.isMethodVerified());
            assertEquals(MFAMethodType.AUTH_APP.getValue(), result.getMfaMethodType());
            assertEquals(AUTH_APP_CREDENTIAL, result.getCredentialValue());
        }

        @Test
        void shouldReturnAtMaximumMfaErrorWhenAddingBackupWithTwoExistingMfaMethods() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new RequestSmsMfaDetail(
                                            PHONE_NUMBER_WITH_COUNTRY_CODE, "123456")));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(
                    MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST,
                    result.getFailure());
        }

        @Test
        void shouldReturnPhoneNumberAlreadyExistsErrorWhenSmsMfaUserAddsBackupWithSameNumber() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new RequestSmsMfaDetail(
                                            PHONE_NUMBER_WITH_COUNTRY_CODE, "123456")));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS, result.getFailure());
        }

        @Test
        void
                shouldReturnPhoneNumberAlreadyExistsErrorWhenSmsMfaUserAddsBackupWithSameNumberWithoutCountryCode() {
            userStoreExtension.addMfaMethodSupportingMultiple(
                    EMAIL,
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            PHONE_NUMBER_WITH_COUNTRY_CODE,
                            PriorityIdentifier.DEFAULT,
                            "some-id"));

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new RequestSmsMfaDetail(
                                            PHONE_NUMBER_WITHOUT_COUNTRY_CODE, "123456")));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS, result.getFailure());
        }

        @Test
        void
                shouldReturnInvalidPhoneNumberErrorWhenPhoneNumberCannotBeConvertedToOneWithCountryCode() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new RequestSmsMfaDetail(
                                            "this is not a phone number", "123456")));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.INVALID_PHONE_NUMBER, result.getFailure());
        }

        @Test
        void shouldReturnAuthAppAlreadyExistsErrorWhenAuthAppMfaUserAddsSecondAuthAppMfa() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new RequestAuthAppMfaDetail(AUTH_APP_CREDENTIAL)));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.AUTH_APP_EXISTS, result.getFailure());
        }

        @Nested
        class WhenMigratingAUser {
            @Test
            void shouldErrorIfPhoneNumberAlreadyMigrated() {
                // Arrange
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addVerifiedPhoneNumber(
                        EMAIL, defaultPrioritySms.getDestination());

                // Act
                var mfaMigrationFailureReason =
                        mfaMethodsService.migrateMfaCredentialsForUser(EMAIL);

                // Assert
                assertEquals(
                        MfaMigrationFailureReason.ALREADY_MIGRATED,
                        mfaMigrationFailureReason.get());
            }
        }
    }

    @Nested
    class UpdateMfaMethod {

        private static final RequestAuthAppMfaDetail authAppDetail =
                new RequestAuthAppMfaDetail(AUTH_APP_CREDENTIAL);
        private static final RequestSmsMfaDetail REQUEST_SMS_MFA_DETAIL =
                new RequestSmsMfaDetail(PHONE_NUMBER_WITH_COUNTRY_CODE, "123456");
        private static final RequestSmsMfaDetail REQUEST_SMS_MFA_DETAIL_WITHOUT_COUNTRY_CODE =
                new RequestSmsMfaDetail(PHONE_NUMBER_WITHOUT_COUNTRY_CODE, "123456");

        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
        }

        @Test
        void returnsAnErrorWhenTheMfaIdentifierIsNotFound() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var request =
                    MfaMethodCreateOrUpdateRequest.from(PriorityIdentifier.BACKUP, authAppDetail);

            var result = mfaMethodsService.updateMfaMethod(EMAIL, "some-other-identifier", request);

            assertEquals(MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER, result.getFailure());

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
            assertEquals(List.of(defaultPriorityAuthApp), remainingMfaMethods);
        }

        @Nested
        class WhenUpdatingADefaultMethod {
            @Test
            void returnsSuccessAndUpdatesMethodWhenAttemptingToUpdateAnAuthAppCredential() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedCredential =
                        new RequestAuthAppMfaDetail(AUTH_APP_CREDENTIAL_TWO);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, detailWithUpdatedCredential);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPriorityAuthApp.getMfaIdentifier(), request);

                var expectedUpdatedDefaultMethod =
                        MFAMethod.authAppMfaMethod(
                                AUTH_APP_CREDENTIAL_TWO,
                                defaultPriorityAuthApp.isMethodVerified(),
                                defaultPriorityAuthApp.isEnabled(),
                                PriorityIdentifier.valueOf(defaultPriorityAuthApp.getPriority()),
                                defaultPriorityAuthApp.getMfaIdentifier());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                var expectedRemainingMethods =
                        List.of(expectedUpdatedDefaultMethod, backupPrioritySms);
                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedRemainingMethods, result.getSuccess()));

                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedRemainingMethods, remainingMfaMethods));
            }

            private static Stream<Arguments> phoneNumbersToPhoneNumbersWithCountryCodes() {
                var phoneNumberThree = "07900000300";
                var phoneNumberThreeWithCountryCode = "+447900000300";
                return Stream.of(
                        Arguments.of(
                                phoneNumberThreeWithCountryCode, phoneNumberThreeWithCountryCode),
                        Arguments.of(phoneNumberThree, phoneNumberThreeWithCountryCode));
            }

            @ParameterizedTest
            @MethodSource("phoneNumbersToPhoneNumbersWithCountryCodes")
            void returnsSuccessWhenAttemptingToUpdateAnSmsNumberWithOrWithoutACountryCode(
                    String phoneNumberInRequest, String expectedStoredPhoneNumber) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedNumber =
                        new RequestSmsMfaDetail(phoneNumberInRequest, "123456");
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, detailWithUpdatedNumber);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPrioritySms.getMfaIdentifier(), request);

                var expectedUpdatedDefaultMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                expectedStoredPhoneNumber,
                                PriorityIdentifier.DEFAULT,
                                defaultPrioritySms.getMfaIdentifier());

                var methodsInDatabase = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                var expectedMethods = List.of(expectedUpdatedDefaultMethod, backupPrioritySms);

                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedMethods, result.getSuccess()));
                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedMethods, methodsInDatabase));
            }

            @ParameterizedTest
            @MethodSource("phoneNumbersToPhoneNumbersWithCountryCodes")
            void
                    returnsFailureWhenAttemptingToUpdateAnSmsNumberToTheBackupNumberRegardlessOfWhetherCountryCodeIncluded(
                            String phoneNumberInRequest,
                            String phoneNumberInRequestWithCountryCode) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                var backupSms =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                phoneNumberInRequestWithCountryCode,
                                PriorityIdentifier.BACKUP,
                                backupPrioritySms.getMfaIdentifier());
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupSms);

                var detailWithUpdatedNumber =
                        new RequestSmsMfaDetail(phoneNumberInRequest, "123456");
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, detailWithUpdatedNumber);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPrioritySms.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER,
                        result.getFailure());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).getSuccess().stream()
                                .sorted()
                                .toList();
                var expectedMethods = Stream.of(backupSms, defaultPrioritySms).sorted().toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            @Test
            void returnsAnErrorWhenAttemptingToUpdateWithAnInvalidNumber() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT,
                                new RequestSmsMfaDetail("not a real phone number", "123456"));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPrioritySms.getMfaIdentifier(), request);

                assertEquals(MfaUpdateFailureReason.INVALID_PHONE_NUMBER, result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(defaultPrioritySms), remainingMfaMethods);
            }

            @Test
            void returnsAnErrorWhenAttemptingToChangePriorityOfDefaultMethod() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, authAppDetail);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPriorityAuthApp.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(defaultPriorityAuthApp), remainingMfaMethods);
            }

            private static Stream<Arguments> existingMethodsAndRequestedUpdates() {
                return Stream.of(
                        Arguments.of(defaultPriorityAuthApp, REQUEST_SMS_MFA_DETAIL),
                        Arguments.of(defaultPrioritySms, authAppDetail));
            }

            @ParameterizedTest
            @MethodSource("existingMethodsAndRequestedUpdates")
            void returnsAFailureWhenAttemptingToChangeTypeOfExistingDefaultMethod(
                    MFAMethod existingMethod, MfaDetail requestedUpdate) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, existingMethod);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, requestedUpdate);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, existingMethod.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(existingMethod), remainingMfaMethods);
            }

            private static Stream<Arguments> existingMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(defaultPriorityAuthApp, authAppDetail),
                        Arguments.of(defaultPrioritySms, REQUEST_SMS_MFA_DETAIL),
                        Arguments.of(
                                defaultPrioritySms, REQUEST_SMS_MFA_DETAIL_WITHOUT_COUNTRY_CODE));
            }

            @ParameterizedTest
            @MethodSource("existingMethodsAndNoChangeUpdates")
            void returnsAFailureWhenNoChangeDetected(
                    MFAMethod existingMethod, MfaDetail requestedUpdate) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, existingMethod);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, requestedUpdate);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, existingMethod.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(existingMethod), remainingMfaMethods);
            }
        }

        @Nested
        class WhenUpdatingABackupMethod {
            @Test
            void successfullySwitchesPriorityOfDefaultAndBackupMethods() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT,
                                new RequestSmsMfaDetail(
                                        backupPrioritySms.getDestination(), "123456"));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);
                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

                var expectedDefaultMethod =
                        MFAMethod.smsMfaMethod(
                                backupPrioritySms.isMethodVerified(),
                                backupPrioritySms.isEnabled(),
                                backupPrioritySms.getDestination(),
                                PriorityIdentifier.DEFAULT,
                                backupPrioritySms.getMfaIdentifier());
                var expectedBackupMethod =
                        MFAMethod.authAppMfaMethod(
                                defaultPriorityAuthApp.getCredentialValue(),
                                defaultPriorityAuthApp.isMethodVerified(),
                                defaultPriorityAuthApp.isEnabled(),
                                PriorityIdentifier.BACKUP,
                                defaultPriorityAuthApp.getMfaIdentifier());
                var expectedMethodsAfterUpdate =
                        Stream.of(expectedDefaultMethod, expectedBackupMethod).sorted().toList();

                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedMethodsAfterUpdate, result.getSuccess()));

                assertTrue(
                        mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
                                expectedMethodsAfterUpdate, remainingMfaMethods));
            }

            private static Stream<Arguments> existingBackupMethodsAndRequestedUpdates() {
                return Stream.of(
                        Arguments.of(backupPriorityAuthApp, REQUEST_SMS_MFA_DETAIL),
                        Arguments.of(backupPrioritySms, authAppDetail));
            }

            @ParameterizedTest
            @MethodSource("existingBackupMethodsAndRequestedUpdates")
            void returnsAFailureWhenAttemptingToChangeTypeOfExistingBackupMethod(
                    MFAMethod existingMethod, MfaDetail requestedUpdate) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, existingMethod);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, requestedUpdate);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, existingMethod.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(existingMethod), remainingMfaMethods);
            }

            @Test
            void returnsAFailureWhenPhoneNumberIsInvalid() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP,
                                new RequestSmsMfaDetail("not a real phone number", "123456"));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);

                assertEquals(MfaUpdateFailureReason.INVALID_PHONE_NUMBER, result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(
                        Stream.of(backupPrioritySms, defaultPrioritySms).sorted().toList(),
                        remainingMfaMethods.stream().sorted().toList());
            }

            private static Stream<Arguments> existingBackupMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(
                                backupPriorityAuthApp,
                                new RequestAuthAppMfaDetail(
                                        backupPriorityAuthApp.getCredentialValue())),
                        Arguments.of(
                                backupPrioritySms,
                                new RequestSmsMfaDetail(
                                        backupPrioritySms.getDestination(), "123456")),
                        Arguments.of(
                                MFAMethod.smsMfaMethod(
                                        true,
                                        true,
                                        PHONE_NUMBER_TWO_WITH_COUNTRY_CODE,
                                        PriorityIdentifier.BACKUP,
                                        backupPrioritySms.getMfaIdentifier()),
                                new RequestSmsMfaDetail(
                                        PHONE_NUMBER_TWO_WITHOUT_COUNTRY_CODE, "123456")));
            }

            @ParameterizedTest
            @MethodSource("existingBackupMethodsAndNoChangeUpdates")
            void returnsAFailureWhenNoChangeDetectedForBackupMethod(
                    MFAMethod existingMethod, MfaDetail requestedUpdate) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, existingMethod);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, requestedUpdate);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, existingMethod.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(existingMethod), remainingMfaMethods);
            }

            @Test
            void returnsFailureWhenAttemptingToUpdateAnSmsNumberForABackup() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedNumber = new RequestSmsMfaDetail("07900000111", "123456");
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, detailWithUpdatedNumber);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_PHONE_NUMBER,
                        result.getFailure());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).getSuccess().stream()
                                .sorted()
                                .toList();
                var expectedMethods =
                        Stream.of(backupPrioritySms, defaultPrioritySms).sorted().toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            @Test
            void returnsFailureWhenAttemptingToUpdateAnAuthAppCredentialForABackup() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPriorityAuthApp);

                var detailWithUpdatedCredential =
                        new RequestAuthAppMfaDetail("a-very-different-credential");
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, detailWithUpdatedCredential);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPriorityAuthApp.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_METHOD_AUTH_APP_CREDENTIAL,
                        result.getFailure());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).getSuccess().stream()
                                .sorted()
                                .toList();
                var expectedMethods =
                        Stream.of(backupPriorityAuthApp, defaultPrioritySms).sorted().toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            private static Stream<Arguments> existingMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(
                                backupPriorityAuthApp,
                                new RequestAuthAppMfaDetail(
                                        backupPriorityAuthApp.getCredentialValue())),
                        Arguments.of(
                                backupPrioritySms,
                                new RequestSmsMfaDetail(
                                        backupPrioritySms.getDestination(), "123456")));
            }

            @ParameterizedTest
            @MethodSource("existingMethodsAndNoChangeUpdates")
            void returnsAFailureWhenNoChangeDetected(
                    MFAMethod existingMethod, MfaDetail requestedUpdate) {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, existingMethod);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.BACKUP, requestedUpdate);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, existingMethod.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(existingMethod), remainingMfaMethods);
            }

            @Test
            void returnsAFailureWhenAttemptingToUpdateABackupWithoutADefault() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT,
                                new RequestSmsMfaDetail(
                                        backupPrioritySms.getDestination(), "123456"));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(backupPrioritySms), remainingMfaMethods);
            }
        }
    }

    @Nested
    class DeleteMfaMethod {
        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
        }

        @Test
        void shouldDeleteABackupAuthAppMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPriorityAuthApp);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
            userProfile = userStoreExtension.getUserProfileFromEmail(EMAIL).get();

            var identifierToDelete = backupPriorityAuthApp.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(identifierToDelete, userProfile);

            assertEquals(Result.success(identifierToDelete), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(List.of(defaultPrioritySms), remainingMfaMethods);
        }

        @Test
        void shouldDeleteABackupSmsMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
            userProfile = userStoreExtension.getUserProfileFromEmail(EMAIL).get();

            var identifierToDelete = backupPrioritySms.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(identifierToDelete, userProfile);

            assertEquals(Result.success(identifierToDelete), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(List.of(defaultPriorityAuthApp), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteADefaultMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));
            userProfile = userStoreExtension.getUserProfileFromEmail(EMAIL).get();

            var identifierToDelete = defaultPriorityAuthApp.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(identifierToDelete, userProfile);

            assertEquals(
                    Result.failure(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(mfaMethods, remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAnyMethodsAndReturnAnAppropriateResultWhenMfaMethodDoesNotExist() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));
            userProfile = userStoreExtension.getUserProfileFromEmail(EMAIL).get();

            var identifierToDelete = "5f27adb6-32ae-4397-a223-4b76840ddd01";

            var result = mfaMethodsService.deleteMfaMethod(identifierToDelete, userProfile);

            assertEquals(
                    Result.failure(
                            MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST),
                    result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            assertEquals(mfaMethods, remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAnyMethodsAndReturnAnAppropriateResultWhenUserIsNotMigrated() {
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.addAuthAppMethodWithIdentifier(
                    EMAIL, true, true, "some-credential", mfaIdentifier);
            userProfile = userStoreExtension.getUserProfileFromEmail(EMAIL).get();
            var methodsBeforeDelete = userStoreExtension.getMfaMethod(EMAIL);

            var result = mfaMethodsService.deleteMfaMethod(mfaIdentifier, userProfile);

            assertEquals(
                    Result.failure(
                            MfaDeleteFailureReason.CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER),
                    result);

            var methodsAfterDelete = userStoreExtension.getMfaMethod(EMAIL);

            assertEquals(methodsBeforeDelete, methodsAfterDelete);
        }
    }

    private boolean mfaMethodsAreEqualIgnoringUpdated(MFAMethod mfaMethod1, MFAMethod mfaMethod2) {
        return mfaMethod1.getMfaIdentifier().equals(mfaMethod2.getMfaIdentifier())
                && mfaMethod1.getPriority().equals(mfaMethod2.getPriority())
                && mfaMethod1.isMethodVerified() == mfaMethod2.isMethodVerified()
                && mfaMethod1.isEnabled() == mfaMethod2.isEnabled()
                && mfaMethod1.getMfaMethodType().equals(mfaMethod2.getMfaMethodType())
                && Objects.equals(mfaMethod1.getCredentialValue(), mfaMethod2.getCredentialValue())
                && Objects.equals(mfaMethod1.getDestination(), mfaMethod2.getDestination());
    }

    private boolean mfaMethodListsContainTheSameItemsIgnoringUpdatedField(
            List<MFAMethod> list1, List<MFAMethod> list2) {
        var sortedList1 = list1.stream().sorted().toList();
        var sortedList2 = list2.stream().sorted().toList();
        return list1.size() == list2.size()
                && IntStream.range(0, list1.size())
                        .allMatch(
                                i ->
                                        mfaMethodsAreEqualIgnoringUpdated(
                                                sortedList1.get(i), sortedList2.get(i)));
    }
}
