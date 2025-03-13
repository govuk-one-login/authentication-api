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
import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.AuthAppMfaData;
import uk.gov.di.authentication.shared.entity.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.MfaData;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaData;
import uk.gov.di.authentication.shared.entity.SmsMfaDetail;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.DynamoMfaMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.services.mfa.DynamoMfaMethodsService.HARDCODED_APP_MFA_ID;
import static uk.gov.di.authentication.shared.services.mfa.DynamoMfaMethodsService.HARDCODED_SMS_MFA_ID;

class DynamoMfaMethodsServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@example.com";
    private static final String PHONE_NUMBER = "+44123456789";
    private static final String AUTH_APP_CREDENTIAL = "some-credential";
    DynamoMfaMethodsService dynamoService =
            new DynamoMfaMethodsService(ConfigurationService.getInstance());

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

            var result = dynamoService.getMfaMethods(email);

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

            var result = dynamoService.getMfaMethods(email);

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

            var result = dynamoService.getMfaMethods(email);

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

            var result = dynamoService.getMfaMethods(email);

            assertEquals(result, List.of());
        }

        @ParameterizedTest
        @ValueSource(strings = {EMAIL, EXPLICITLY_NON_MIGRATED_USER_EMAIL})
        void shouldReturnNoMethodsWhenSmsMethodNotVerified(String email) {
            userStoreExtension.setPhoneNumberAndVerificationStatus(
                    email, PHONE_NUMBER, false, true);

            var result = dynamoService.getMfaMethods(email);

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

        private static final AuthAppMfaData defaultPriorityAuthApp =
                new AuthAppMfaData(
                        AUTH_APP_CREDENTIAL,
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        APP_MFA_IDENTIFIER_1);
        private static final String AUTH_APP_CREDENTIAL_TWO = "another-credential";
        private static final AuthAppMfaData backupPriorityAuthApp =
                new AuthAppMfaData(
                        AUTH_APP_CREDENTIAL_TWO,
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        APP_MFA_IDENTIFIER_2);
        private static final SmsMfaData defaultPrioritySms =
                new SmsMfaData(
                        PHONE_NUMBER, true, true, PriorityIdentifier.DEFAULT, SMS_MFA_IDENTIFIER_1);
        private static final SmsMfaData backupPrioritySms =
                new SmsMfaData(
                        PHONE_NUMBER_TWO,
                        true,
                        true,
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

            var result = dynamoService.getMfaMethods(EMAIL);

            var expectedData = mfaMethodDataFrom(defaultPrioritySms);
            assertEquals(List.of(expectedData), result);
        }

        @Test
        void shouldReturnSingleAuthAppMethodWhenEnabled() {
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var result = dynamoService.getMfaMethods(EMAIL);

            var expectedData = mfaMethodDataFrom(defaultPriorityAuthApp);
            assertEquals(result, List.of(expectedData));
        }

        private static Stream<List<MfaData>> mfaMethodsCombinations() {
            return Stream.of(
                    List.of(defaultPriorityAuthApp, backupPriorityAuthApp),
                    List.of(defaultPrioritySms, backupPrioritySms),
                    List.of(defaultPriorityAuthApp, backupPrioritySms),
                    List.of(defaultPrioritySms, backupPriorityAuthApp));
        }

        @ParameterizedTest
        @MethodSource("mfaMethodsCombinations")
        void shouldReturnMultipleMethodsWhenTheyExist(List<MfaData> mfaMethods) {
            mfaMethods.forEach(
                    mfaMethod ->
                            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, mfaMethod));

            var result = dynamoService.getMfaMethods(EMAIL);

            var expectedData =
                    mfaMethods.stream()
                            .map(DynamoMfaMethodsServiceIntegrationTest::mfaMethodDataFrom)
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

                var result = dynamoService.addBackupMfa(TEST_EMAIL, mfaMethod);

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
                        () -> dynamoService.addBackupMfa(TEST_EMAIL, request.mfaMethod()));
            }

            @Test
            void shouldReturnNullWhenAuthAppMfaAdded() throws InvalidPriorityIdentifierException {
                AuthAppMfaDetail authAppMfaDetail =
                        new AuthAppMfaDetail(MFAMethodType.AUTH_APP, AUTH_APP_CREDENTIAL);

                MfaMethodCreateRequest request =
                        new MfaMethodCreateRequest(
                                new MfaMethodCreateRequest.MfaMethod(
                                        PriorityIdentifier.BACKUP, authAppMfaDetail));

                var result = dynamoService.addBackupMfa(TEST_EMAIL, request.mfaMethod());
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

        private static final AuthAppMfaData defaultPriorityAuthApp =
                new AuthAppMfaData(
                        AUTH_APP_CREDENTIAL,
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        APP_MFA_IDENTIFIER_1);
        private static final String AUTH_APP_CREDENTIAL_TWO = "another-credential";
        private static final AuthAppMfaData backupPriorityAuthApp =
                new AuthAppMfaData(
                        AUTH_APP_CREDENTIAL_TWO,
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        APP_MFA_IDENTIFIER_2);
        private static final SmsMfaData defaultPrioritySms =
                new SmsMfaData(
                        PHONE_NUMBER, true, true, PriorityIdentifier.DEFAULT, SMS_MFA_IDENTIFIER_1);
        private static final SmsMfaData backupPrioritySms =
                new SmsMfaData(
                        PHONE_NUMBER_TWO,
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        SMS_MFA_IDENTIFIER_2);

        @BeforeEach
        void setUp() {
            userStoreExtension.signUp(EMAIL, "password-1", new Subject());
        }

        @Test
        void shouldDeleteABackupAuthAppMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPriorityAuthApp);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPrioritySms);

            var identifierToDelete = backupPriorityAuthApp.mfaIdentifier();

            var result = dynamoService.deleteMfaMethod(EMAIL, identifierToDelete);

            assertEquals(Either.right(identifierToDelete), result);

            var remainingMfaMethods = dynamoService.getMfaMethods(EMAIL);

            assertEquals(List.of(mfaMethodDataFrom(defaultPrioritySms)), remainingMfaMethods);
        }

        @Test
        void shouldDeleteABackupSmsMfaMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, backupPrioritySms);
            userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, defaultPriorityAuthApp);

            var identifierToDelete = backupPrioritySms.mfaIdentifier();

            var result = dynamoService.deleteMfaMethod(EMAIL, identifierToDelete);

            assertEquals(Either.right(identifierToDelete), result);

            var remainingMfaMethods = dynamoService.getMfaMethods(EMAIL);

            assertEquals(List.of(mfaMethodDataFrom(defaultPriorityAuthApp)), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAPriorityMethodForAMigratedUser() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));

            var identifierToDelete = defaultPriorityAuthApp.mfaIdentifier();

            var result = dynamoService.deleteMfaMethod(EMAIL, identifierToDelete);

            assertEquals(Either.left(MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD), result);

            var remainingMfaMethods = dynamoService.getMfaMethods(EMAIL);

            var expectedRemainingMfaMethods =
                    mfaMethods.stream()
                            .map(DynamoMfaMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
        }

        @Test
        void shouldNotDeleteAnyMethodsAndReturnAnAppropriateResultWhenMfaMethodDoesNotExist() {
            userStoreExtension.setMfaMethodsMigrated(EMAIL, true);
            var mfaMethods = List.of(backupPrioritySms, defaultPriorityAuthApp);
            mfaMethods.forEach(m -> userStoreExtension.addMfaMethodSupportingMultiple(EMAIL, m));

            var identifierToDelete = "5f27adb6-32ae-4397-a223-4b76840ddd01";

            var result = dynamoService.deleteMfaMethod(EMAIL, identifierToDelete);

            assertEquals(
                    Either.left(MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST),
                    result);

            var remainingMfaMethods = dynamoService.getMfaMethods(EMAIL);

            var expectedRemainingMfaMethods =
                    mfaMethods.stream()
                            .map(DynamoMfaMethodsServiceIntegrationTest::mfaMethodDataFrom);

            assertEquals(expectedRemainingMfaMethods.toList(), remainingMfaMethods);
        }
    }

    private static MfaMethodData mfaMethodDataFrom(MfaData mfaData) {
        if (mfaData instanceof AuthAppMfaData authAppMfaData) {
            var detail = new AuthAppMfaDetail(MFAMethodType.AUTH_APP, authAppMfaData.credential());
            return new MfaMethodData(
                    authAppMfaData.mfaIdentifier(),
                    authAppMfaData.priority(),
                    authAppMfaData.verified(),
                    detail);
        } else {
            SmsMfaData smsMfaData = (SmsMfaData) mfaData;
            var detail = new SmsMfaDetail(MFAMethodType.SMS, smsMfaData.endpoint());
            return new MfaMethodData(
                    smsMfaData.mfaIdentifier(),
                    smsMfaData.priority(),
                    smsMfaData.verified(),
                    detail);
        }
    }
}
