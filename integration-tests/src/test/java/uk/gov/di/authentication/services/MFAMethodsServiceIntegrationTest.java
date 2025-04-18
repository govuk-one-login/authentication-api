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
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MFAMethodsServiceIntegrationTest {

    private static final String EMAIL = "joe.bloggs@example.com";
    private static final String PHONE_NUMBER = "+44123456789";
    private static final String PHONE_NUMBER_TWO = "987654321";
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
                    true, true, PHONE_NUMBER, PriorityIdentifier.DEFAULT, SMS_MFA_IDENTIFIER_1);
    private static final MFAMethod backupPrioritySms =
            MFAMethod.smsMfaMethod(
                    true, true, PHONE_NUMBER_TWO, PriorityIdentifier.BACKUP, SMS_MFA_IDENTIFIER_2);
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
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.setPhoneNumberMfaIdentifer(email, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);
            var expectedData =
                    new MfaMethodData(
                            mfaIdentifier, PriorityIdentifier.DEFAULT, true, smsMfaDetail);
            assertEquals(result, List.of(expectedData));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldStoreAnMfaIdentifierForANonMigratedSmsMethodOnRead(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            userProfile = userStoreExtension.getUserProfileFromEmail(email).get();
            var mfaIdentifier = userProfile.getMfaIdentifier();
            assertFalse(mfaIdentifier.isEmpty());

            var smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);
            var expectedData =
                    new MfaMethodData(
                            mfaIdentifier, PriorityIdentifier.DEFAULT, true, smsMfaDetail);
            assertEquals(result, List.of(expectedData));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnSingleAuthAppMethodWhenEnabled(String email) {
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.addAuthAppMethodWithIdentifier(
                    email, true, true, AUTH_APP_CREDENTIAL, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var authAppDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
            var expectedData =
                    new MfaMethodData(
                            mfaIdentifier, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(result, List.of(expectedData));
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

            var authAppDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
            var expectedData =
                    new MfaMethodData(
                            mfaIdentifier, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(result, List.of(expectedData));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void authAppShouldTakePrecedenceOverSmsMethodForNonMigratedUser(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);
            var mfaIdentifier = UUID.randomUUID().toString();
            userStoreExtension.addAuthAppMethodWithIdentifier(
                    email, true, true, AUTH_APP_CREDENTIAL, mfaIdentifier);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            var authAppDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
            var expectedData =
                    new MfaMethodData(
                            mfaIdentifier, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(List.of(expectedData), result);
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
                    email, PHONE_NUMBER, false, true);

            var result = mfaMethodsService.getMfaMethods(email).getSuccess();

            assertEquals(result, List.of());
        }

        @Nested
        class WhenMigratingAUser {
            @ParameterizedTest
            @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
            void shouldMigrateActiveSmsNeedingMigration(String email) {
                // Arrange
                userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);

                var credentialsMfaMethodsBefore =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertNull(credentialsMfaMethodsBefore);

                UserProfile userProfileBefore =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertFalse(userProfileBefore.getMfaMethodsMigrated());
                assertEquals(PHONE_NUMBER, userProfileBefore.getPhoneNumber());
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
                assertEquals(PHONE_NUMBER, credentialSmsMfaMethod.getDestination());
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
                userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);
                var existingIdentifier = UUID.randomUUID().toString();
                userStoreExtension.setPhoneNumberMfaIdentifer(email, existingIdentifier);

                var credentialsMfaMethodsBefore =
                        userStoreExtension.getUserCredentialsFromEmail(email).get().getMfaMethods();
                assertNull(credentialsMfaMethodsBefore);

                UserProfile userProfileBefore =
                        userStoreExtension.getUserProfileFromEmail(email).get();

                assertFalse(userProfileBefore.getMfaMethodsMigrated());
                assertEquals(PHONE_NUMBER, userProfileBefore.getPhoneNumber());
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
                assertEquals(PHONE_NUMBER, credentialSmsMfaMethod.getDestination());
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
                userStoreExtension.addVerifiedPhoneNumber(EMAIL, PHONE_NUMBER);

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

            var expectedData = mfaMethodDataFrom(defaultPrioritySms);
            assertEquals(List.of(expectedData), result);
        }

        @Test
        void shouldReturnSingleAuthAppMethodWhenEnabled() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var result = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

            var expectedData = mfaMethodDataFrom(defaultPriorityAuthApp);
            assertEquals(result, List.of(expectedData));
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

            var expectedData =
                    mfaMethods.stream()
                            .map(MFAMethodsServiceIntegrationTest::mfaMethodDataFrom)
                            .toList();
            assertEquals(expectedData, result);
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
            SmsMfaDetail smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, smsMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MFAMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .getSuccess();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MFAMethodsServiceIntegrationTest.EMAIL);
            boolean smsMethodExists =
                    mfaMethods.stream()
                            .anyMatch(
                                    method ->
                                            method.getMfaMethodType()
                                                    .equals(MFAMethodType.SMS.getValue()));

            assertTrue(smsMethodExists);
            assertDoesNotThrow(() -> UUID.fromString(result.mfaIdentifier()));
            assertEquals(PriorityIdentifier.BACKUP, result.priorityIdentifier());
            assertTrue(result.methodVerified());
            assertEquals(smsMfaDetail, result.method());
        }

        @Test
        void smsUserShouldSuccessfullyAddAuthAppMfa() {
            userStoreExtension.addMfaMethodSupportingMultiple(
                    MFAMethodsServiceIntegrationTest.EMAIL, defaultPrioritySms);

            AuthAppMfaDetail authAppMfaDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, authAppMfaDetail);

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
            assertDoesNotThrow(() -> UUID.fromString(result.mfaIdentifier()));
            assertEquals(PriorityIdentifier.BACKUP, result.priorityIdentifier());
            assertTrue(result.methodVerified());
            assertEquals(authAppMfaDetail, result.method());
        }

        @Test
        void shouldReturnAtMaximumMfaErrorWhenAddingBackupWithTwoExistingMfaMethods() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP, new SmsMfaDetail(PHONE_NUMBER)));

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
                                    PriorityIdentifier.BACKUP, new SmsMfaDetail(PHONE_NUMBER)));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MFAMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS, result.getFailure());
        }

        @Test
        void shouldReturnAuthAppAlreadyExistsErrorWhenAuthAppMfaUserAddsSecondAuthAppMfa() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.BACKUP,
                                    new AuthAppMfaDetail(AUTH_APP_CREDENTIAL)));

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

        private static final AuthAppMfaDetail authAppDetail =
                new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
        private static final SmsMfaDetail smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);

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
            assertEquals(List.of(mfaMethodDataFrom(defaultPriorityAuthApp)), remainingMfaMethods);
        }

        @Nested
        class WhenUpdatingADefaultMethod {
            @Test
            void returnsSuccessAndUpdatesMethodWhenAttemptingToUpdateAnAuthAppCredential() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedCredential = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL_TWO);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, detailWithUpdatedCredential);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPriorityAuthApp.getMfaIdentifier(), request);

                var expectedUpdatedDefaultMethod =
                        MfaMethodData.authAppMfaData(
                                defaultPriorityAuthApp.getMfaIdentifier(),
                                PriorityIdentifier.DEFAULT,
                                true,
                                AUTH_APP_CREDENTIAL_TWO);

                var expectedUnchangedBackupMethod =
                        MfaMethodData.from(backupPrioritySms).getSuccess();

                assertEquals(
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod)
                                .stream()
                                .sorted()
                                .toList(),
                        result.getSuccess());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                var expectedRemainingMethods =
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod);
                assertEquals(
                        expectedRemainingMethods.stream().sorted().toList(),
                        remainingMfaMethods.stream().sorted().toList());
            }

            @Test
            void returnsSuccessWhenAttemptingToUpdateAnSmsNumber() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var aThirdPhoneNumber = "111222333";

                var detailWithUpdatedNumber = new SmsMfaDetail(aThirdPhoneNumber);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT, detailWithUpdatedNumber);

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, defaultPrioritySms.getMfaIdentifier(), request);

                var expectedUpdatedDefaultMethod =
                        MfaMethodData.smsMethodData(
                                defaultPrioritySms.getMfaIdentifier(),
                                PriorityIdentifier.DEFAULT,
                                true,
                                aThirdPhoneNumber);

                var expectedUnchangedBackupMethod =
                        MfaMethodData.from(backupPrioritySms).getSuccess();

                assertEquals(
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod)
                                .stream()
                                .sorted()
                                .toList(),
                        result.getSuccess());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).getSuccess().stream()
                                .sorted()
                                .toList();
                var expectedMethods =
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod)
                                .stream()
                                .sorted()
                                .toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            @Test
            void returnsFailureWhenAttemptingToUpdateAnSmsNumberToTheBackupNumber() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedNumber = new SmsMfaDetail(backupPrioritySms.getDestination());
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
                var expectedMethods =
                        List.of(
                                        mfaMethodDataFrom(backupPrioritySms),
                                        mfaMethodDataFrom(defaultPrioritySms))
                                .stream()
                                .sorted()
                                .toList();
                assertEquals(expectedMethods, methodsInDatabase);
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
                assertEquals(
                        List.of(mfaMethodDataFrom(defaultPriorityAuthApp)), remainingMfaMethods);
            }

            private static Stream<Arguments> existingMethodsAndRequestedUpdates() {
                return Stream.of(
                        Arguments.of(defaultPriorityAuthApp, smsMfaDetail),
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
                assertEquals(List.of(mfaMethodDataFrom(existingMethod)), remainingMfaMethods);
            }

            private static Stream<Arguments> existingMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(defaultPriorityAuthApp, authAppDetail),
                        Arguments.of(defaultPrioritySms, smsMfaDetail));
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
                assertEquals(List.of(mfaMethodDataFrom(existingMethod)), remainingMfaMethods);
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
                                new SmsMfaDetail(backupPrioritySms.getDestination()));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);
                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();

                var expectedDefaultMethod =
                        MfaMethodData.smsMethodData(
                                backupPrioritySms.getMfaIdentifier(),
                                PriorityIdentifier.DEFAULT,
                                backupPrioritySms.isMethodVerified(),
                                backupPrioritySms.getDestination());
                var expectedBackupMethod =
                        MfaMethodData.authAppMfaData(
                                defaultPriorityAuthApp.getMfaIdentifier(),
                                PriorityIdentifier.BACKUP,
                                defaultPriorityAuthApp.isMethodVerified(),
                                defaultPriorityAuthApp.getCredentialValue());
                var expectedMethodsAfterUpdate =
                        Stream.of(expectedDefaultMethod, expectedBackupMethod).sorted().toList();

                assertEquals(
                        expectedMethodsAfterUpdate, result.getSuccess().stream().sorted().toList());

                assertEquals(
                        expectedMethodsAfterUpdate, remainingMfaMethods.stream().sorted().toList());
            }

            private static Stream<Arguments> existingBackupMethodsAndRequestedUpdates() {
                return Stream.of(
                        Arguments.of(backupPriorityAuthApp, smsMfaDetail),
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
                assertEquals(List.of(mfaMethodDataFrom(existingMethod)), remainingMfaMethods);
            }

            private static Stream<Arguments> existingBackupMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(
                                backupPriorityAuthApp,
                                new AuthAppMfaDetail(backupPriorityAuthApp.getCredentialValue())),
                        Arguments.of(
                                backupPrioritySms,
                                new SmsMfaDetail(backupPrioritySms.getDestination())));
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
                assertEquals(List.of(mfaMethodDataFrom(existingMethod)), remainingMfaMethods);
            }

            @Test
            void returnsFailureWhenAttemptingToUpdateAnSmsNumberForABackup() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);

                var detailWithUpdatedNumber = new SmsMfaDetail("07900000111");
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
                        List.of(
                                        mfaMethodDataFrom(backupPrioritySms),
                                        mfaMethodDataFrom(defaultPrioritySms))
                                .stream()
                                .sorted()
                                .toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            @Test
            void returnsFailureWhenAttemptingToUpdateAnAuthAppCredentialForABackup() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPriorityAuthApp);

                var detailWithUpdatedCredential =
                        new AuthAppMfaDetail("a-very-different-credential");
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
                        List.of(
                                        mfaMethodDataFrom(backupPriorityAuthApp),
                                        mfaMethodDataFrom(defaultPrioritySms))
                                .stream()
                                .sorted()
                                .toList();
                assertEquals(expectedMethods, methodsInDatabase);
            }

            private static Stream<Arguments> existingMethodsAndNoChangeUpdates() {
                return Stream.of(
                        Arguments.of(
                                backupPriorityAuthApp,
                                new AuthAppMfaDetail(backupPriorityAuthApp.getCredentialValue())),
                        Arguments.of(
                                backupPrioritySms,
                                new SmsMfaDetail(backupPrioritySms.getDestination())));
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
                assertEquals(List.of(mfaMethodDataFrom(existingMethod)), remainingMfaMethods);
            }

            @Test
            void returnsAFailureWhenAttemptingToUpdateABackupWithoutADefault() {
                userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
                var request =
                        MfaMethodCreateOrUpdateRequest.from(
                                PriorityIdentifier.DEFAULT,
                                new SmsMfaDetail(backupPrioritySms.getDestination()));

                var result =
                        mfaMethodsService.updateMfaMethod(
                                EMAIL, backupPrioritySms.getMfaIdentifier(), request);

                assertEquals(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD,
                        result.getFailure());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL).getSuccess();
                assertEquals(List.of(mfaMethodDataFrom(backupPrioritySms)), remainingMfaMethods);
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

            assertEquals(List.of(mfaMethodDataFrom(defaultPrioritySms)), remainingMfaMethods);
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

            assertEquals(List.of(mfaMethodDataFrom(defaultPriorityAuthApp)), remainingMfaMethods);
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

            var expectedRemainingMfaMethods =
                    mfaMethods.stream().map(MFAMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
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

            var expectedRemainingMfaMethods =
                    mfaMethods.stream().map(MFAMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
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

    private static MfaMethodData mfaMethodDataFrom(MFAMethod mfaMethod) {
        MfaDetail detail;
        if (mfaMethod.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue())) {
            detail = new AuthAppMfaDetail(mfaMethod.getCredentialValue());

        } else {
            detail = new SmsMfaDetail(mfaMethod.getDestination());
        }
        return new MfaMethodData(
                mfaMethod.getMfaIdentifier(),
                PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                mfaMethod.isMethodVerified(),
                detail);
    }
}
