package uk.gov.di.authentication.frontendapi.entity;

import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public class AuthenticatorApp extends AbstractMfaMethod implements MfaAttemptsStore {

    private static final List<JourneyType> SUPPORTED_JOURNEY_TYPES =
            List.of(JourneyType.REGISTRATION, JourneyType.SIGN_IN, JourneyType.ACCOUNT_RECOVERY);

    public AuthenticatorApp(ConfigurationService configurationService, JourneyType journeyType) {
        super(configurationService, journeyType);
        validateJourneyTypes(SUPPORTED_JOURNEY_TYPES);
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
        return MFAMethodType.EMAIL;
    }
}
