package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.hasInternationalPhoneNumber;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.FORCED_MFA_RESET_INITIATED;
import static uk.gov.di.authentication.shared.entity.JourneyType.PASSWORD_RESET_MFA;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.JourneyType.SIGN_IN;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ForcedMfaResetHelper {

    private static final Logger LOG = LogManager.getLogger(ForcedMfaResetHelper.class);

    private ForcedMfaResetHelper() {}

    public static boolean isMfaResetRequired(
            ConfigurationService configurationService, List<MFAMethod> mfaMethods) {
        return configurationService.isForcedMFAResetAfterMFACheckEnabled()
                && hasInternationalPhoneNumber(mfaMethods);
    }

    public static boolean isInitiatedJourney(JourneyType journeyType) {
        return (journeyType == SIGN_IN
                || journeyType == REAUTHENTICATION
                || journeyType == PASSWORD_RESET_MFA);
    }

    public static void emitRequestedAuditEventAndMetric(
            ConfigurationService configurationService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            JourneyType journeyType,
            Optional<MFAMethod> activeMfaMethod,
            AuditContext auditContext) {
        var activeSmsMethod =
                activeMfaMethod.filter(
                        m -> MFAMethodType.SMS.getValue().equals(m.getMfaMethodType()));

        String destination =
                activeSmsMethod.map(MFAMethod::getDestination).orElse(AuditService.UNKNOWN);

        String countryCode =
                activeSmsMethod
                        .map(MFAMethod::getDestination)
                        .flatMap(PhoneNumberHelper::maybeGetCountry)
                        .orElse(AuditService.UNKNOWN);

        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED,
                auditContext.withPhoneNumber(destination),
                pair(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, countryCode),
                pair(
                        AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                        MfaResetType.FORCED_INTERNATIONAL_NUMBERS),
                pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, JourneyType.ACCOUNT_RECOVERY));

        emitMetric(FORCED_MFA_RESET_INITIATED, configurationService, cloudwatchMetricsService);

        LOG.info(
                "User has international phone number on account, initiating forced MFA reset. JourneyType: {}, CountryCode (for active method): {}.",
                journeyType,
                countryCode);
    }

    private static void emitMetric(
            CloudwatchMetrics metricName,
            ConfigurationService configurationService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        cloudwatchMetricsService.incrementCounter(
                metricName.getValue(),
                Map.of(
                        ENVIRONMENT.getValue(),
                        configurationService.getEnvironment(),
                        MFA_RESET_TYPE.getValue(),
                        MfaResetType.FORCED_INTERNATIONAL_NUMBERS.toString()));
    }
}
