package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.NoDefaultMfaMethodLogHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.NONE;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class MfaHelperTest {
    private static final UserCredentials userCredentials = mock(UserCredentials.class);
    private static final String PHONE_NUMBER = "+44123456789";
    private static final UserProfile userProfile = mock(UserProfile.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(MfaHelper.class);

    @RegisterExtension
    private final CaptureLoggingExtension noDefaultMfaMethodLogging =
            new CaptureLoggingExtension(NoDefaultMfaMethodLogHelper.class);

    @Nested
    class GetUserMFADetail {
        private static Stream<Arguments> trustLevelsToMfaRequired() {
            return Stream.of(
                    Arguments.of(CredentialTrustLevel.LOW_LEVEL, false),
                    Arguments.of(CredentialTrustLevel.MEDIUM_LEVEL, true));
        }

        @ParameterizedTest
        @MethodSource("trustLevelsToMfaRequired")
        void isMfaRequiredShouldReflectLevelOfTrustRequested(
                CredentialTrustLevel trustLevel, boolean expectedMfaRequired) {
            setupUserProfile(userProfile, PHONE_NUMBER, true, false);
            var result = getUserMFADetail(trustLevel, userCredentials, userProfile);

            assertEquals(expectedMfaRequired, result.isMfaRequired());
        }

        @Test
        void shouldReturnAVerifiedSmsMethodWhenNoAuthAppExists() {
            var isPhoneNumberVerified = true;
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            when(userCredentials.getMfaMethods()).thenReturn(List.of());

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining(format("User has mfa method %s", "SMS"))));
        }

        @Test
        void shouldReturnAVerifiedSmsMethodWhenAuthAppExistsButIsNotEnabled() {
            var isPhoneNumberVerified = true;
            var isAuthAppEnabled = false;
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            var authApp = authAppMfaMethod(true, isAuthAppEnabled);
            when(userCredentials.getMfaMethods()).thenReturn(List.of(authApp));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);
        }

        @Test
        void shouldReturnMethodTypeOfNoneWhenSmsMethodNotVerified() {
            var isPhoneNumberVerified = false;
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            when(userCredentials.getMfaMethods()).thenReturn(List.of());

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, false, NONE, PHONE_NUMBER);

            assertEquals(expectedResult, result);

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining(format("User has mfa method %s", "NONE"))));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void
                shouldReturnAuthAppMethodWhenOneExistsWhichIsEnabledRegardlessOfWhetherPhoneNumberVerified(
                        boolean isPhoneNumberVerified) {
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            var isAuthAppVerified = true;

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(isAuthAppVerified, true)));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult =
                    new UserMfaDetail(true, true, MFAMethodType.AUTH_APP, PHONE_NUMBER);

            assertEquals(expectedResult, result);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "User has verified method from user credentials")));
        }

        @Test
        void shouldReturnVerifiedSMSMethodWhenAuthAppExistsButIsNotVerified() {
            var isPhoneNumberVerified = true;
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(false, true)));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);
        }

        @Test
        void shouldReturnUnVerifiedAuthMethodWhenPhoneNumberIsNotVerified() {
            var isAuthAppVerified = false;
            var isPhoneNumberVerified = false;
            setupUserProfile(userProfile, PHONE_NUMBER, isPhoneNumberVerified, false);

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(isAuthAppVerified, true)));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, false, AUTH_APP, PHONE_NUMBER);

            assertEquals(expectedResult, result);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Unverified auth app mfa method present and no verified phone number")));
        }

        @Test
        void shouldReturnRelevantMethodForAMigratedUser() {
            when(userProfile.isMfaMethodsMigrated()).thenReturn(true);

            var phoneNumberOfMigratedMethod = "+447900000000";
            var isPhoneNumberVerifiedOnUserProfile = false;
            setupUserProfile(userProfile, null, isPhoneNumberVerifiedOnUserProfile, true);

            var defaultSmsMethod =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            phoneNumberOfMigratedMethod,
                            PriorityIdentifier.DEFAULT,
                            "some-mfa-identifier");

            var backupAuthAppMethod =
                    MFAMethod.authAppMfaMethod(
                            "some-credential",
                            true,
                            true,
                            PriorityIdentifier.BACKUP,
                            "auth-app-mfa-id");

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(defaultSmsMethod, backupAuthAppMethod));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, true, SMS, phoneNumberOfMigratedMethod);

            assertEquals(expectedResult, result);
        }

        @Test
        void shouldHandleErrorsRetrievingADefaultMethodForAMigratedUser() {
            when(userProfile.isMfaMethodsMigrated()).thenReturn(true);

            var isPhoneNumberVerifiedOnUserProfile = false;
            setupUserProfile(userProfile, null, isPhoneNumberVerifiedOnUserProfile, true);

            var backupAuthAppMethod =
                    MFAMethod.authAppMfaMethod(
                            "some-credential",
                            true,
                            true,
                            PriorityIdentifier.BACKUP,
                            "auth-app-mfa-id");
            when(userCredentials.getMfaMethods()).thenReturn(List.of(backupAuthAppMethod));

            var result =
                    getUserMFADetail(
                            CredentialTrustLevel.MEDIUM_LEVEL, userCredentials, userProfile);
            var expectedResult = new UserMfaDetail(true, false, NONE, null);

            assertEquals(expectedResult, result);

            assertThat(
                    noDefaultMfaMethodLogging.events(),
                    hasItem(
                            withMessageContaining(
                                    "No default mfa method found for user. Is user migrated: true, user MFA method count: 1, MFA method priority-type pairs: (BACKUP,AUTH_APP).")));
        }
    }

    @Nested
    class RetrieveDefaultMethodForMigratedUser {
        private static final MFAMethod defaultPriorityAuthApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential-1",
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        "some-auth-app-identifier-1");
        private static final MFAMethod backupPriorityAuthApp =
                MFAMethod.authAppMfaMethod(
                        "some-credential-2",
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        "some-auth-app-identifier-1");
        private static final MFAMethod defaultPrioritySms =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        "some-sms-identifier-1");
        private static final MFAMethod backupPrioritySms =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        "+447900000100",
                        PriorityIdentifier.BACKUP,
                        "some-sms-identifier-2");

        private static Stream<Arguments> mfaMethodsCombinations() {
            return Stream.of(
                    Arguments.of(
                            List.of(defaultPriorityAuthApp, backupPriorityAuthApp),
                            defaultPriorityAuthApp),
                    Arguments.of(
                            List.of(defaultPrioritySms, backupPrioritySms), defaultPrioritySms),
                    Arguments.of(
                            List.of(defaultPriorityAuthApp, backupPrioritySms),
                            defaultPriorityAuthApp),
                    Arguments.of(
                            List.of(defaultPrioritySms, backupPriorityAuthApp),
                            defaultPrioritySms));
        }

        @ParameterizedTest
        @MethodSource("mfaMethodsCombinations")
        void shouldReturnADefaultMethod(
                List<MFAMethod> mfaMethods, MFAMethod expectedRetrievedDefault) {
            var userCredentialsWithMigratedMethods =
                    new UserCredentials().withMfaMethods(mfaMethods);

            var result =
                    MfaHelper.getDefaultMfaMethodForMigratedUser(
                            userCredentialsWithMigratedMethods);

            assertEquals(Optional.of(expectedRetrievedDefault), result);
        }

        @Test
        void shouldReturnAFailureIfNoDefaultMethodExists() {
            var userCredentialsWithBackupMethodOnly =
                    new UserCredentials().withMfaMethods(List.of(backupPrioritySms));

            var result =
                    MfaHelper.getDefaultMfaMethodForMigratedUser(
                            userCredentialsWithBackupMethodOnly);

            assertEquals(Optional.empty(), result);
        }
    }

    private static MFAMethod authAppMfaMethod(boolean isAuthAppVerified, boolean enabled) {
        return new MFAMethod(
                MFAMethodType.AUTH_APP.getValue(),
                "some-credential",
                isAuthAppVerified,
                enabled,
                NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
    }

    private static void setupUserProfile(
            UserProfile userProfile,
            String phoneNumber,
            boolean isPhoneNumberVerified,
            boolean areMfaMethodsMigrated) {
        when(userProfile.getPhoneNumber()).thenReturn(phoneNumber);
        when(userProfile.isPhoneNumberVerified()).thenReturn(isPhoneNumberVerified);
        when(userProfile.isMfaMethodsMigrated()).thenReturn(areMfaMethodsMigrated);
    }
}
