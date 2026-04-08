package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_METHOD_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.FORCED_MFA_RESET_COMPLETED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.FORCED_MFA_RESET_INITIATED;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_AUTH_APP_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;

class ForcedMfaResetHelperTest {

    private static final MFAMethod DEFAULT_INTERNATIONAL_SMS_METHOD =
            new MFAMethod(DEFAULT_SMS_METHOD).withDestination(INTERNATIONAL_MOBILE_NUMBER);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuditContext auditContext = AuditContext.emptyAuditContext();

    @Nested
    class IsMfaResetRequired {
        @Test
        void shouldReturnTrueWhenFeatureFlagEnabledAndInternationalNumber() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            List<MFAMethod> mfaMethods = List.of(DEFAULT_INTERNATIONAL_SMS_METHOD);

            assertTrue(ForcedMfaResetHelper.isMfaResetRequired(configurationService, mfaMethods));
        }

        @Test
        void shouldReturnTrueWhenFeatureFlagEnabledAndMultipleMfaMethodsWithInternationalNumber() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            MFAMethod backupInternationalSmsMethod =
                    new MFAMethod(BACKUP_SMS_METHOD).withDestination(INTERNATIONAL_MOBILE_NUMBER);
            List<MFAMethod> mfaMethods = List.of(DEFAULT_SMS_METHOD, backupInternationalSmsMethod);

            assertTrue(ForcedMfaResetHelper.isMfaResetRequired(configurationService, mfaMethods));
        }

        @Test
        void shouldReturnFalseWhenFeatureFlagDisabled() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(false);

            List<MFAMethod> mfaMethods = List.of(DEFAULT_INTERNATIONAL_SMS_METHOD);

            assertFalse(ForcedMfaResetHelper.isMfaResetRequired(configurationService, mfaMethods));
        }

        @Test
        void shouldReturnFalseWhenPhoneNumberIsDomestic() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            List<MFAMethod> mfaMethods = List.of(DEFAULT_SMS_METHOD);

            assertFalse(ForcedMfaResetHelper.isMfaResetRequired(configurationService, mfaMethods));
        }

        @Test
        void shouldReturnFalseWhenMfaMethodsListIsEmpty() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);

            assertFalse(ForcedMfaResetHelper.isMfaResetRequired(configurationService, List.of()));
        }
    }

    @Nested
    class IsInitiatedJourney {
        static Stream<JourneyType> validJourneyTypes() {
            return Stream.of(
                    JourneyType.SIGN_IN,
                    JourneyType.REAUTHENTICATION,
                    JourneyType.PASSWORD_RESET_MFA);
        }

        @ParameterizedTest
        @MethodSource("validJourneyTypes")
        void shouldReturnTrueForValidJourneyType(JourneyType journeyType) {
            assertTrue(ForcedMfaResetHelper.isInitiatedJourney(journeyType));
        }

        @ParameterizedTest
        @EnumSource(
                value = JourneyType.class,
                names = {"SIGN_IN", "REAUTHENTICATION", "PASSWORD_RESET_MFA"},
                mode = EnumSource.Mode.EXCLUDE)
        void shouldReturnFalseForInvalidJourneyType(JourneyType journeyType) {
            assertFalse(ForcedMfaResetHelper.isInitiatedJourney(journeyType));
        }
    }

    @Nested
    class EmitRequestedAuditEventAndMetric {
        private static final String TEST_ENVIRONMENT = "test-environment";

        @BeforeEach
        void setup() {
            when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
        }

        @Test
        void shouldEmitAuditEventWithExpectedInternationalNumberMetadata() {
            ForcedMfaResetHelper.emitRequestedAuditEventAndMetric(
                    configurationService,
                    auditService,
                    cloudwatchMetricsService,
                    JourneyType.SIGN_IN,
                    Optional.of(DEFAULT_INTERNATIONAL_SMS_METHOD),
                    auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(INTERNATIONAL_MOBILE_NUMBER)),
                            eq(pair(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, "7")),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }

        @Test
        void shouldEmitAuditEventWithUnknownPhoneWhenActiveMfaMethodIsNotSms() {
            ForcedMfaResetHelper.emitRequestedAuditEventAndMetric(
                    configurationService,
                    auditService,
                    cloudwatchMetricsService,
                    JourneyType.SIGN_IN,
                    Optional.of(DEFAULT_AUTH_APP_METHOD),
                    auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                            AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }

        @Test
        void shouldEmitAuditEventWithUnknownPhoneWhenActiveMfaMethodIsEmpty() {
            ForcedMfaResetHelper.emitRequestedAuditEventAndMetric(
                    configurationService,
                    auditService,
                    cloudwatchMetricsService,
                    JourneyType.SIGN_IN,
                    Optional.empty(),
                    auditContext);

            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(auditContext.withPhoneNumber(AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                            AuditService.UNKNOWN)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
        }

        @Test
        void shouldIncrementMetric() {
            ForcedMfaResetHelper.emitRequestedAuditEventAndMetric(
                    configurationService,
                    auditService,
                    cloudwatchMetricsService,
                    JourneyType.SIGN_IN,
                    Optional.of(DEFAULT_INTERNATIONAL_SMS_METHOD),
                    auditContext);

            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            FORCED_MFA_RESET_INITIATED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    MFA_RESET_TYPE.getValue(),
                                    MfaResetType.FORCED_INTERNATIONAL_NUMBERS.toString()));
        }
    }

    @Nested
    class EmitCompletedMetric {
        private static final String TEST_ENVIRONMENT = "test-environment";

        @BeforeEach
        void setup() {
            when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
        }

        @Test
        void shouldIncrementMetric() {
            MFAMethodType newMfaMethodType = MFAMethodType.SMS;

            ForcedMfaResetHelper.emitCompletedMetric(
                    configurationService, cloudwatchMetricsService, newMfaMethodType);

            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            FORCED_MFA_RESET_COMPLETED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    MFA_RESET_TYPE.getValue(),
                                    MfaResetType.FORCED_INTERNATIONAL_NUMBERS.toString(),
                                    MFA_METHOD_TYPE.getValue(),
                                    newMfaMethodType.getValue()));
        }
    }
}
