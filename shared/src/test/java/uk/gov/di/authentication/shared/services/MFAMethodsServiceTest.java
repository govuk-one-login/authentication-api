package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest.MfaMethod;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.NoDefaultMfaMethodLogHelper;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

public class MFAMethodsServiceTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsService.class);

    @RegisterExtension
    private final CaptureLoggingExtension noDefaultMfaMethodLogging =
            new CaptureLoggingExtension(NoDefaultMfaMethodLogHelper.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService persistentService = mock(AuthenticationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private final UserProfile userProfile = new UserProfile().withMfaMethodsMigrated(true);

    private static final String TEST_PHONE_NUMBER = "01234567890";

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
    }

    @Nested
    class GetMfaMethodOrDefault {
        @Test
        void shouldReturnDefaultMFAMethodIfNoIdProvided() {
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            List.of(DEFAULT_SMS_METHOD), null, null);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_SMS_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldFilterOnMfaMethodType() {
            List<MFAMethod> mfaMethods = List.of(DEFAULT_AUTH_APP_METHOD, DEFAULT_SMS_METHOD);

            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, null, MFAMethodType.SMS);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_SMS_METHOD, maybeDefaultMfaMethod.get());

            maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, null, MFAMethodType.AUTH_APP);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(DEFAULT_AUTH_APP_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldReturnIdentifiedMfaIfPresent() {
            List<MFAMethod> mfaMethods = List.of(BACKUP_AUTH_APP_METHOD, DEFAULT_SMS_METHOD);
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, BACKUP_AUTH_APP_METHOD.getMfaIdentifier(), null);
            assertTrue(maybeDefaultMfaMethod.isPresent());
            assertEquals(BACKUP_AUTH_APP_METHOD, maybeDefaultMfaMethod.get());
        }

        @Test
        void shouldReturnEmptyIfIdentifiedMfaIsNotPresent() {
            List<MFAMethod> mfaMethods = List.of(DEFAULT_SMS_METHOD);
            Optional<MFAMethod> maybeDefaultMfaMethod =
                    MFAMethodsService.getMfaMethodOrDefaultMfaMethod(
                            mfaMethods, BACKUP_AUTH_APP_METHOD.getMfaIdentifier(), null);
            assertTrue(maybeDefaultMfaMethod.isEmpty());
        }
    }

    @Nested
    class GetMfaMethod {
        @Test
        void shouldReturnIdentifiedMfaAndAllMfas() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            mockUserCredentials.setMfaMethods(List.of(DEFAULT_SMS_METHOD, BACKUP_AUTH_APP_METHOD));
            when(persistentService.getUserCredentialsFromEmail(EMAIL))
                    .thenReturn(mockUserCredentials);
            when(persistentService.getUserProfileByEmail(EMAIL)).thenReturn(userProfile);

            var result =
                    service.getMfaMethod(EMAIL, DEFAULT_SMS_METHOD.getMfaIdentifier()).getSuccess();

            assertEquals(DEFAULT_SMS_METHOD, result.mfaMethod());
            assertIterableEquals(
                    List.of(DEFAULT_SMS_METHOD, BACKUP_AUTH_APP_METHOD), result.allMfaMethods());
        }

        @Test
        void returnsAnErrorWhenTheMfaIdentifierIsNotFound() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            mockUserCredentials.setMfaMethods(List.of(DEFAULT_SMS_METHOD, BACKUP_AUTH_APP_METHOD));
            when(persistentService.getUserCredentialsFromEmail(EMAIL))
                    .thenReturn(mockUserCredentials);
            when(persistentService.getUserProfileByEmail(EMAIL)).thenReturn(userProfile);

            var result = service.getMfaMethod(EMAIL, "some-other-identifier").getFailure();

            assertEquals(MfaRetrieveFailureReason.UNKNOWN_MFA_IDENTIFIER, result);
        }

        @Test
        void logsAnErrorIfPriorityIdentifierIsNull() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            MFAMethod defaultMfaMethodWithNullPriority =
                    MFAMethod.smsMfaMethod(
                                    true,
                                    true,
                                    UK_MOBILE_NUMBER,
                                    PriorityIdentifier.DEFAULT,
                                    "default-sms-identifier")
                            .withPriority(null);
            mockUserCredentials.setMfaMethods(
                    List.of(defaultMfaMethodWithNullPriority, BACKUP_AUTH_APP_METHOD));
            when(persistentService.getUserCredentialsFromEmail(EMAIL))
                    .thenReturn(mockUserCredentials);
            when(persistentService.getUserProfileByEmail(EMAIL)).thenReturn(userProfile);

            service.getMfaMethod(EMAIL, DEFAULT_SMS_METHOD.getMfaIdentifier()).getSuccess();

            assertThat(
                    noDefaultMfaMethodLogging.events(),
                    hasItem(
                            withMessageContaining(
                                    "No default mfa method found for user. Is user migrated: unknown, user MFA method count: 2, MFA method priority-type pairs: (absent_attribute,SMS), (BACKUP,AUTH_APP).")));
        }
    }

    @Nested
    class DeleteMfaMethod {

        @Test
        void shouldIncrementMfaMethodCounterForDeleteMfaMethodCase() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            var mockMfaMethods = new ArrayList<MFAMethod>();
            var identifier = UUID.randomUUID().toString();
            mockMfaMethods.add(
                    MFAMethod.authAppMfaMethod("some-credential", true, true, BACKUP, identifier));
            mockUserCredentials.setMfaMethods(mockMfaMethods);
            when(persistentService.getUserCredentialsFromEmail(any()))
                    .thenReturn(mockUserCredentials);

            service.deleteMfaMethod(identifier, userProfile);

            verify(cloudwatchMetricsService)
                    .incrementMfaMethodCounter(
                            "test",
                            "DeleteMfaMethod",
                            "SUCCESS",
                            ACCOUNT_MANAGEMENT,
                            "AUTH_APP",
                            BACKUP);
        }
    }

    @Nested
    class UpdateMfaMethod {

        @Test
        void shouldIncrementMfaMethodCounterForUpdateMfaMethodCase() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            var mockMfaMethods = new ArrayList<MFAMethod>();
            var identifier = UUID.randomUUID().toString();
            var mfaMethod =
                    MFAMethod.smsMfaMethod(true, true, TEST_PHONE_NUMBER, DEFAULT, identifier);
            mockMfaMethods.add(mfaMethod);
            mockUserCredentials.setMfaMethods(mockMfaMethods);
            var mfaDetail = new RequestSmsMfaDetail(TEST_PHONE_NUMBER, "123123");
            var request = new MfaMethodUpdateRequest(new MfaMethod(DEFAULT, mfaDetail));
            when(persistentService.getUserCredentialsFromEmail(any()))
                    .thenReturn(mockUserCredentials);
            when(persistentService.updateMfaMethods(any(), any()))
                    .thenReturn(Result.success(mockMfaMethods));

            service.updateMfaMethod("some-email@email.com", mfaMethod, mockMfaMethods, request);

            verify(cloudwatchMetricsService)
                    .incrementMfaMethodCounter(
                            "test",
                            "UpdateMfaMethod",
                            "SUCCESS",
                            ACCOUNT_MANAGEMENT,
                            "SMS",
                            DEFAULT);
        }

        @Test
        void shouldIncrementMfaMethodCounterForSwapBackupWithDefaultMfaMethodCase() {
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            var mockMfaMethods = new ArrayList<MFAMethod>();
            var defaultIdentifier = UUID.randomUUID().toString();
            var backupIdentifier = UUID.randomUUID().toString();
            var defaultMfaMethod =
                    MFAMethod.smsMfaMethod(
                            true, true, TEST_PHONE_NUMBER, DEFAULT, defaultIdentifier);
            var backupMfaMethod =
                    MFAMethod.authAppMfaMethod(
                            "some-credential", true, true, BACKUP, backupIdentifier);
            mockMfaMethods.add(defaultMfaMethod);
            mockMfaMethods.add(backupMfaMethod);
            mockUserCredentials.setMfaMethods(mockMfaMethods);
            var request = new MfaMethodUpdateRequest(new MfaMethod(null, null));
            when(persistentService.getUserCredentialsFromEmail(any()))
                    .thenReturn(mockUserCredentials);
            when(persistentService.updateAllMfaMethodsForUser(any(), any()))
                    .thenReturn(Result.success(mockMfaMethods));

            service.updateMfaMethod(
                    "some-email@email.com", backupMfaMethod, mockMfaMethods, request);

            verify(cloudwatchMetricsService)
                    .incrementMfaMethodCounter(
                            "test",
                            "SwapBackupWithDefaultMfaMethod",
                            "SUCCESS",
                            ACCOUNT_MANAGEMENT,
                            "AUTH_APP",
                            BACKUP);
        }
    }
}
