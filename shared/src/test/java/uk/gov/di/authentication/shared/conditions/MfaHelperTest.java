package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.conditions.MfaHelper.getUserMFADetail;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.NONE;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class MfaHelperTest {
    private static final UserCredentials userCredentials = mock(UserCredentials.class);
    private static final String PHONE_NUMBER = "+44123456789";
    private static final UserProfile userProfile = mock(UserProfile.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(MfaHelper.class);

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
            var userContext = userContextWithLevelOfTrustRequested(trustLevel);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var result =
                    getUserMFADetail(userContext, userCredentials, PHONE_NUMBER, true, userProfile);

            assertEquals(expectedMfaRequired, result.isMfaRequired());
        }

        @Test
        void shouldReturnAVerifiedSmsMethodWhenNoAuthAppExists() {
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isPhoneNumberVerified = true;

            when(userCredentials.getMfaMethods()).thenReturn(List.of());

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining(format("User has mfa method %s", "SMS"))));
        }

        @Test
        void shouldReturnAVerifiedSmsMethodWhenAuthAppExistsButIsNotEnabled() {
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isPhoneNumberVerified = true;
            var isAuthAppEnabled = false;

            var authApp = authAppMfaMethod(true, isAuthAppEnabled);
            when(userCredentials.getMfaMethods()).thenReturn(List.of(authApp));

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);
        }

        @Test
        void shouldReturnMethodTypeOfNoneWhenSmsMethodNotVerified() {
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isPhoneNumberVerified = false;

            when(userCredentials.getMfaMethods()).thenReturn(List.of());

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
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
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isAuthAppVerified = true;

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(isAuthAppVerified, true)));

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
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
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isPhoneNumberVerified = true;

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(false, true)));

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
            var expectedResult = new UserMfaDetail(true, isPhoneNumberVerified, SMS, PHONE_NUMBER);

            assertEquals(expectedResult, result);
        }

        @Test
        void shouldReturnUnVerifiedAuthMethodWhenPhoneNumberIsNotVerified() {
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(false);

            var isAuthAppVerified = false;
            var isPhoneNumberVerified = false;

            when(userCredentials.getMfaMethods())
                    .thenReturn(List.of(authAppMfaMethod(isAuthAppVerified, true)));

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
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
            var userContext =
                    userContextWithLevelOfTrustRequested(CredentialTrustLevel.MEDIUM_LEVEL);
            when(userProfile.getMfaMethodsMigrated()).thenReturn(true);

            var phoneNumberOfMigratedMethod = "+447900000000";

            var isPhoneNumberVerified = false;

            when(userCredentials.getMfaMethods())
                    .thenReturn(
                            List.of(
                                    MFAMethod.smsMfaMethod(
                                            true,
                                            true,
                                            phoneNumberOfMigratedMethod,
                                            PriorityIdentifier.DEFAULT,
                                            "some-mfa-identifier"),
                                    MFAMethod.authAppMfaMethod(
                                            "some-credential",
                                            true,
                                            true,
                                            PriorityIdentifier.BACKUP,
                                            "auth-app-mfa-id")));

            var result =
                    getUserMFADetail(
                            userContext,
                            userCredentials,
                            PHONE_NUMBER,
                            isPhoneNumberVerified,
                            userProfile);
            var expectedResult = new UserMfaDetail(true, true, SMS, phoneNumberOfMigratedMethod);

            assertEquals(expectedResult, result);
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

    private static UserContext userContextWithLevelOfTrustRequested(
            CredentialTrustLevel trustLevel) {
        var clientSession = mock(ClientSession.class);
        var authRequestParams = generateAuthRequest(trustLevel).toParameters();
        when(clientSession.getAuthRequestParams()).thenReturn(authRequestParams);

        var userContext = mock(UserContext.class);
        when(userContext.getClientSession()).thenReturn(clientSession);

        return userContext;
    }

    private static AuthenticationRequest generateAuthRequest(
            CredentialTrustLevel credentialTrustLevel) {
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID("CLIENT_ID"),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        if (nonNull(credentialTrustLevel)) {
            builder.customParameter("vtr", jsonArrayOf(credentialTrustLevel.getValue()));
        }
        return builder.build();
    }

    private static MFAMethod authAppMfaMethod(boolean isAuthAppVerified, boolean enabled) {
        return new MFAMethod(
                MFAMethodType.AUTH_APP.getValue(),
                "some-credential",
                isAuthAppVerified,
                enabled,
                NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
    }
}
