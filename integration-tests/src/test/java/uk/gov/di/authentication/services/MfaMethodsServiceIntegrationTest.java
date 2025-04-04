package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.entity.*;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodCreateOrUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
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
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_APP_MFA_ID;
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_SMS_MFA_ID;

class MfaMethodsServiceIntegrationTest {

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
    MfaMethodsService mfaMethodsService = new MfaMethodsService(ConfigurationService.getInstance());

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

            var result = mfaMethodsService.getMfaMethods(email);

            var authAppDetail = new SmsMfaDetail(PHONE_NUMBER);
            var expectedData =
                    new MfaMethodData(
                            HARDCODED_SMS_MFA_ID, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(result, List.of(expectedData));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnSingleAuthAppMethodWhenEnabled(String email) {
            userStoreExtension.addAuthAppMethod(email, true, true, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email);

            var authAppDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
            var expectedData =
                    new MfaMethodData(
                            HARDCODED_APP_MFA_ID, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(result, List.of(expectedData));
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void authAppShouldTakePrecedenceOverSmsMethodForNonMigratedUser(String email) {
            userStoreExtension.addVerifiedPhoneNumber(email, PHONE_NUMBER);
            userStoreExtension.addAuthAppMethod(email, true, true, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email);

            var authAppDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);
            var expectedData =
                    new MfaMethodData(
                            HARDCODED_APP_MFA_ID, PriorityIdentifier.DEFAULT, true, authAppDetail);
            assertEquals(List.of(expectedData), result);
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenAuthAppMethodNotEnabled(String email) {
            userStoreExtension.addAuthAppMethod(email, true, false, AUTH_APP_CREDENTIAL);

            var result = mfaMethodsService.getMfaMethods(email);

            assertEquals(result, List.of());
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenSmsMethodNotVerified(String email) {
            userStoreExtension.setPhoneNumberAndVerificationStatus(
                    email, PHONE_NUMBER, false, true);

            var result = mfaMethodsService.getMfaMethods(email);

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

            var result = mfaMethodsService.getMfaMethods(EMAIL);

            var expectedData = mfaMethodDataFrom(defaultPrioritySms);
            assertEquals(List.of(expectedData), result);
        }

        @Test
        void shouldReturnSingleAuthAppMethodWhenEnabled() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var result = mfaMethodsService.getMfaMethods(EMAIL);

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

            var result = mfaMethodsService.getMfaMethods(EMAIL);

            var expectedData =
                    mfaMethods.stream()
                            .map(MfaMethodsServiceIntegrationTest::mfaMethodDataFrom)
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
                    MfaMethodsServiceIntegrationTest.EMAIL, defaultPriorityAuthApp);
            SmsMfaDetail smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, smsMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MfaMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .get();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MfaMethodsServiceIntegrationTest.EMAIL);
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
                    MfaMethodsServiceIntegrationTest.EMAIL, defaultPrioritySms);

            AuthAppMfaDetail authAppMfaDetail = new AuthAppMfaDetail(AUTH_APP_CREDENTIAL);

            MfaMethodCreateOrUpdateRequest.MfaMethod mfaMethod =
                    new MfaMethodCreateOrUpdateRequest.MfaMethod(
                            PriorityIdentifier.BACKUP, authAppMfaDetail);

            var result =
                    mfaMethodsService
                            .addBackupMfa(MfaMethodsServiceIntegrationTest.EMAIL, mfaMethod)
                            .get();

            List<MFAMethod> mfaMethods =
                    userStoreExtension.getMfaMethod(MfaMethodsServiceIntegrationTest.EMAIL);
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
        void shouldErrorWhenPriorityIdentifierIsDefault() {
            userStoreExtension.addAuthAppMethod(
                    MfaMethodsServiceIntegrationTest.EMAIL, true, true, AUTH_APP_CREDENTIAL);
            SmsMfaDetail smsMfaDetail = new SmsMfaDetail(PHONE_NUMBER);

            MfaMethodCreateOrUpdateRequest request =
                    new MfaMethodCreateOrUpdateRequest(
                            new MfaMethodCreateOrUpdateRequest.MfaMethod(
                                    PriorityIdentifier.DEFAULT, smsMfaDetail));

            var result =
                    mfaMethodsService.addBackupMfa(
                            MfaMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.INVALID_PRIORITY_IDENTIFIER, result.getLeft());
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
                            MfaMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(
                    MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST,
                    result.getLeft());
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
                            MfaMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS, result.getLeft());
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
                            MfaMethodsServiceIntegrationTest.EMAIL, request.mfaMethod());

            assertEquals(MfaCreateFailureReason.AUTH_APP_EXISTS, result.getLeft());
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

            assertEquals(MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER, result.getLeft());

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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

                var expectedUnchangedBackupMethod = MfaMethodData.from(backupPrioritySms).get();

                assertEquals(
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod)
                                .stream()
                                .sorted()
                                .toList(),
                        result.get());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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

                var expectedUnchangedBackupMethod = MfaMethodData.from(backupPrioritySms).get();

                assertEquals(
                        List.of(expectedUpdatedDefaultMethod, expectedUnchangedBackupMethod)
                                .stream()
                                .sorted()
                                .toList(),
                        result.get());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).stream().sorted().toList();
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
                        result.getLeft());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).stream().sorted().toList();
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
                        result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD, result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                        result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

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

                assertEquals(expectedMethodsAfterUpdate, result.get().stream().sorted().toList());

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
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD, result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                        result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                        result.getLeft());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).stream().sorted().toList();
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
                        result.getLeft());

                var methodsInDatabase =
                        mfaMethodsService.getMfaMethods(EMAIL).stream().sorted().toList();
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
                        result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
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
                        result.getLeft());

                var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);
                assertEquals(List.of(mfaMethodDataFrom(backupPrioritySms)), remainingMfaMethods);
            }
        }
    }

    @Nested
    class DeleteMfaMethod {
        private String publicSubjectId;

        @BeforeEach
        void setUp() {
            publicSubjectId = userStoreExtension.signUp(EMAIL, "password-1", new Subject());
        }

        @Test
        void shouldDeleteABackupAuthAppMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPriorityAuthApp);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);

            var identifierToDelete = backupPriorityAuthApp.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(publicSubjectId, identifierToDelete);

            assertEquals(Either.right(identifierToDelete), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

            assertEquals(List.of(mfaMethodDataFrom(defaultPrioritySms)), remainingMfaMethods);
        }

        @Test
        void shouldDeleteABackupSmsMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var identifierToDelete = backupPrioritySms.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(publicSubjectId, identifierToDelete);

            assertEquals(Either.right(identifierToDelete), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

            assertEquals(List.of(mfaMethodDataFrom(defaultPriorityAuthApp)), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteADefaultMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));

            var identifierToDelete = defaultPriorityAuthApp.getMfaIdentifier();

            var result = mfaMethodsService.deleteMfaMethod(publicSubjectId, identifierToDelete);

            assertEquals(Either.left(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD), result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

            var expectedRemainingMfaMethods =
                    mfaMethods.stream().map(MfaMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAnyMethodsAndReturnAnAppropriateResultWhenMfaMethodDoesNotExist() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));

            var identifierToDelete = "5f27adb6-32ae-4397-a223-4b76840ddd01";

            var result = mfaMethodsService.deleteMfaMethod(publicSubjectId, identifierToDelete);

            assertEquals(
                    Either.left(MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST),
                    result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

            var expectedRemainingMfaMethods =
                    mfaMethods.stream().map(MfaMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAnyMethodsAndReturnAnAppropriateResultWhenUserIsNotMigrated() {
            userStoreExtension.addMfaMethod(
                    EMAIL, MFAMethodType.AUTH_APP, true, true, "some-credential");

            var result = mfaMethodsService.deleteMfaMethod(publicSubjectId, HARDCODED_APP_MFA_ID);

            assertEquals(
                    Either.left(
                            MfaDeleteFailureReason.CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER),
                    result);

            var remainingMfaMethods = mfaMethodsService.getMfaMethods(EMAIL);

            var expectedRemainingMfaMethod =
                    new MfaMethodData(
                            HARDCODED_APP_MFA_ID,
                            PriorityIdentifier.DEFAULT,
                            true,
                            new AuthAppMfaDetail("some-credential"));

            assertEquals(List.of(expectedRemainingMfaMethod), remainingMfaMethods);
        }

        @Test
        void shouldReturnAnErrorWhenUserProfileNotFoundForPublicSubjectId() {
            var result = mfaMethodsService.deleteMfaMethod("some-other-id", HARDCODED_APP_MFA_ID);

            assertEquals(
                    Either.left(MfaDeleteFailureReason.NO_USER_PROFILE_FOUND_FOR_PUBLIC_SUBJECT_ID),
                    result);
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
