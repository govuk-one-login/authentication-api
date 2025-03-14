package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MfaMethodData;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.SmsMfaDetail;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMethodsService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_APP_MFA_ID;
import static uk.gov.di.authentication.shared.services.mfa.MfaMethodsService.HARDCODED_SMS_MFA_ID;

class MfaMethodsServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@example.com";
    private static final String PHONE_NUMBER = "+44123456789";
    private static final String AUTH_APP_CREDENTIAL = "some-credential";
    MfaMethodsService mfaMethodsService = new MfaMethodsService(ConfigurationService.getInstance());

    @RegisterExtension static UserStoreExtension userStoreExtension = new UserStoreExtension();

    @Nested
    class WhenAUserIsNotMigrated {

        private static final String EMAIL = "joe.bloggs@example.com";
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

            var authAppDetail = new SmsMfaDetail(MFAMethodType.SMS, PHONE_NUMBER);
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

            var authAppDetail = new AuthAppMfaDetail(MFAMethodType.AUTH_APP, AUTH_APP_CREDENTIAL);
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

            var authAppDetail = new AuthAppMfaDetail(MFAMethodType.AUTH_APP, AUTH_APP_CREDENTIAL);
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
    }

    @Nested
    class WhenAUserIsMigrated {

        private static final String EMAIL = "joe.bloggs@example.com";

        private static final String SMS_MFA_IDENTIFIER_1 = "ea83592f-b9bf-436f-b4f4-ee33f610ee05";
        private static final String SMS_MFA_IDENTIFIER_2 = "3634a5e3-dac8-4804-8d40-181722b48ae1";
        private static final String APP_MFA_IDENTIFIER_1 = "a87e57e5-6175-4be7-af7d-547a390b36c1";
        private static final String APP_MFA_IDENTIFIER_2 = "898a7e13-c354-430a-a3ca-8cc6c6391057";
        private static final String PHONE_NUMBER_TWO = "987654321";

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
                        true,
                        true,
                        PHONE_NUMBER_TWO,
                        PriorityIdentifier.BACKUP,
                        SMS_MFA_IDENTIFIER_2);

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

        @Nested
        class AddBackupMfaTests {
            @Test
            void authAppUserShouldSuccessfullyAddSmsMfaInPost()
                    throws InvalidPriorityIdentifierException {
                userStoreExtension.addAuthAppMethod(TEST_EMAIL, true, true, AUTH_APP_CREDENTIAL);
                SmsMfaDetail smsMfaDetail = new SmsMfaDetail(MFAMethodType.SMS, PHONE_NUMBER);

                MfaMethodCreateRequest.MfaMethod mfaMethod =
                        new MfaMethodCreateRequest.MfaMethod(
                                PriorityIdentifier.BACKUP, smsMfaDetail);

                var result = mfaMethodsService.addBackupMfa(TEST_EMAIL, mfaMethod);

                List<MFAMethod> mfaMethods = userStoreExtension.getMfaMethod(TEST_EMAIL);
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
            void shouldErrorWhenPriorityIdentifierIsDefault() {
                userStoreExtension.addAuthAppMethod(TEST_EMAIL, true, true, AUTH_APP_CREDENTIAL);
                SmsMfaDetail smsMfaDetail = new SmsMfaDetail(MFAMethodType.SMS, PHONE_NUMBER);

                MfaMethodCreateRequest request =
                        new MfaMethodCreateRequest(
                                new MfaMethodCreateRequest.MfaMethod(
                                        PriorityIdentifier.DEFAULT, smsMfaDetail));

                assertThrows(
                        InvalidPriorityIdentifierException.class,
                        () -> mfaMethodsService.addBackupMfa(TEST_EMAIL, request.mfaMethod()));
            }

            @Test
            void shouldReturnNullWhenAuthAppMfaAdded() throws InvalidPriorityIdentifierException {
                AuthAppMfaDetail authAppMfaDetail =
                        new AuthAppMfaDetail(MFAMethodType.AUTH_APP, AUTH_APP_CREDENTIAL);

                MfaMethodCreateRequest request =
                        new MfaMethodCreateRequest(
                                new MfaMethodCreateRequest.MfaMethod(
                                        PriorityIdentifier.BACKUP, authAppMfaDetail));

                var result = mfaMethodsService.addBackupMfa(TEST_EMAIL, request.mfaMethod());
                assertNull(result);
            }
        }
    }

    @Nested
    class DeleteMfaMethod {
        private static final String EMAIL = "joe.bloggs@example.com";

        private static final String SMS_MFA_IDENTIFIER_1 = "ea83592f-b9bf-436f-b4f4-ee33f610ee05";
        private static final String SMS_MFA_IDENTIFIER_2 = "3634a5e3-dac8-4804-8d40-181722b48ae1";
        private static final String APP_MFA_IDENTIFIER_1 = "a87e57e5-6175-4be7-af7d-547a390b36c1";
        private static final String APP_MFA_IDENTIFIER_2 = "898a7e13-c354-430a-a3ca-8cc6c6391057";
        private static final String PHONE_NUMBER_TWO = "987654321";

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
                        true,
                        true,
                        PHONE_NUMBER_TWO,
                        PriorityIdentifier.BACKUP,
                        SMS_MFA_IDENTIFIER_2);
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
                            new AuthAppMfaDetail(MFAMethodType.AUTH_APP, "some-credential"));

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
            detail = new AuthAppMfaDetail(MFAMethodType.AUTH_APP, mfaMethod.getCredentialValue());

        } else {
            detail = new SmsMfaDetail(MFAMethodType.SMS, mfaMethod.getDestination());
        }
        return new MfaMethodData(
                mfaMethod.getMfaIdentifier(),
                PriorityIdentifier.valueOf(mfaMethod.getPriority()),
                mfaMethod.isMethodVerified(),
                detail);
    }
}
