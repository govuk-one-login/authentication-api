package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest.MfaMethod;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

public class MFAMethodsServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService persistentService = mock(AuthenticationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";

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
    class DeleteMfaMethod {

        @Test
        void shouldIncrementMfaMethodCounterForDeleteMfaMethodCase() {
            // Given
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var userProfile = new UserProfile();
            userProfile.setMfaMethodsMigrated(true);
            var mockUserCredentials = new UserCredentials();
            var mockMfaMethods = new ArrayList<MFAMethod>();
            var identifier = UUID.randomUUID().toString();
            mockMfaMethods.add(
                    MFAMethod.authAppMfaMethod("some-credential", true, true, BACKUP, identifier));
            mockUserCredentials.setMfaMethods(mockMfaMethods);
            when(persistentService.getUserCredentialsFromEmail(any()))
                    .thenReturn(mockUserCredentials);

            // When
            service.deleteMfaMethod(identifier, userProfile);

            // Then
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
            // Given
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

            // When
            service.updateMfaMethod("some-email@email.com", identifier, request);

            // Then
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
            // Given
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

            // When
            service.updateMfaMethod("some-email@email.com", backupIdentifier, request);

            // Then
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

    @Nested
    class IsAuthAppDefaultMfaMethod {
        @ParameterizedTest
        @CsvSource({
                "DEFAULT, BACKUP, false",
                "BACKUP, DEFAULT, true"
        })
        void shouldCorrectlyIdentifyIfAuthAppIsDefaultMfaMethod(
                PriorityIdentifier smsMfaPriority,
                PriorityIdentifier authMfaPriority,
                Boolean expectedResult
        ) {
            // Given
            var service =
                    new MFAMethodsService(
                            configurationService, persistentService, cloudwatchMetricsService);
            var mockUserCredentials = new UserCredentials();
            var mockMfaMethods = new ArrayList<MFAMethod>();
            var smsIdentifier = UUID.randomUUID().toString();
            var authMfaIdentifier = UUID.randomUUID().toString();
            var smsMfaMethod =
                    MFAMethod.smsMfaMethod(
                            true, true, TEST_PHONE_NUMBER, smsMfaPriority, smsIdentifier);
            var authMfaMethod =
                    MFAMethod.authAppMfaMethod(
                            "some-credential", true, true, authMfaPriority, authMfaIdentifier);
            mockMfaMethods.add(smsMfaMethod);
            mockMfaMethods.add(authMfaMethod);
            mockUserCredentials.setMfaMethods(mockMfaMethods);
            mockUserCredentials.setEmail(TEST_EMAIL_ADDRESS);
            when(persistentService.getUserCredentialsFromEmail(any())).thenReturn(mockUserCredentials);

            // When
            var result = service.isAuthAppDefaultMfaMethod(TEST_EMAIL_ADDRESS);

            // Then
            assertEquals(expectedResult, result);
        }
    }
}
