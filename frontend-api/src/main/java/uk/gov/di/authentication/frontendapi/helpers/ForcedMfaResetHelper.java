package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.conditions.MfaHelper.hasInternationalPhoneNumber;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class ForcedMfaResetHelper {

    private static final Logger LOG = LogManager.getLogger(ForcedMfaResetHelper.class);

    private ForcedMfaResetHelper() {}

    public static void emitForcedMfaResetAuditEventIfRequired(
            ConfigurationService configurationService,
            AuditService auditService,
            JourneyType journeyType,
            List<MFAMethod> mfaMethods,
            Optional<MFAMethod> activeMfaMethod,
            AuditContext auditContext) {
        var excludedJourneys =
                List.of(
                        JourneyType.REGISTRATION,
                        JourneyType.PASSWORD_RESET,
                        JourneyType.ACCOUNT_RECOVERY,
                        JourneyType.ACCOUNT_MANAGEMENT);

        if (!configurationService.isForcedMFAResetAfterMFACheckEnabled()
                || excludedJourneys.contains(journeyType)
                || !hasInternationalPhoneNumber(mfaMethods)) {
            return;
        }

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

        LOG.info(
                "User has international phone number on account, forcing MFA reset. JourneyType: {}, CountryCode (for active method): {}.",
                journeyType,
                countryCode);
    }
}
