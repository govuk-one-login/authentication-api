package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public class Email extends AbstractMfaMethod implements MfaAttemptsStore, MfaRequestStore {

    private static final List<JourneyType> SUPPORTED_JOURNEY_TYPES =
            List.of(JourneyType.REGISTRATION, JourneyType.ACCOUNT_RECOVERY);

    public Email(ConfigurationService configurationService, JourneyType journeyType) {
        super(configurationService, journeyType);
        validateJourneyTypes(SUPPORTED_JOURNEY_TYPES);
    }

    @Override
    public long getOtpExpiryTime() {
        if (journeyType.equals(JourneyType.REGISTRATION)) {
            return configurationService.getEmailAccountCreationOtpCodeExpiry();
        } else {
            return configurationService.getDefaultOtpCodeExpiry();
        }
    }

    @Override
    public long getMaxOtpRequests() {
        return configurationService.getCodeMaxRetries();
    }

    @Override
    public long getMaxOtpInvalidAttempts() {
        return configurationService.getCodeMaxRetries();
    }

    @Override
    public boolean shouldBlockWhenMaxAttemptsReached() {
        return !journeyType.equals(JourneyType.REGISTRATION);
    }

    @Override
    public MFAMethodType getMfaMethodType() {
        return MFAMethodType.EMAIL;
    }
}
