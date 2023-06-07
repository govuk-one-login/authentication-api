package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public class SMS extends AbstractMfaMethod implements MfaAttemptsStore, MfaRequestStore {

    private static final List<JourneyType> SUPPORTED_JOURNEY_TYPES =
            List.of(JourneyType.REGISTRATION, JourneyType.SIGN_IN, JourneyType.ACCOUNT_RECOVERY);

    public SMS(ConfigurationService configurationService, JourneyType journeyType) {
        super(configurationService, journeyType);
        validateJourneyTypes(SUPPORTED_JOURNEY_TYPES);
    }

    @Override
    public long getOtpExpiryTime() {
        return configurationService.getDefaultOtpCodeExpiry();
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
        return true;
    }

    @Override
    public MFAMethodType getMfaMethodType() {
        return MFAMethodType.SMS;
    }
}
