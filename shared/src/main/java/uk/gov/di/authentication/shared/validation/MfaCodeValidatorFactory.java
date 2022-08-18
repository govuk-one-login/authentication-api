package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

public class MfaCodeValidatorFactory {

    private final ConfigurationService configurationService;
    private final CodeStorageService codeStorageService;
    private final AuthenticationService authenticationService;

    public MfaCodeValidatorFactory(
            ConfigurationService configurationService,
            CodeStorageService codeStorageService,
            AuthenticationService authenticationService) {
        this.configurationService = configurationService;
        this.codeStorageService = codeStorageService;
        this.authenticationService = authenticationService;
    }

    public Optional<MfaCodeValidator> getMfaCodeValidator(
            MFAMethodType mfaMethodType, boolean isRegistration, String emailAddress) {

        int codeMaxRetries =
                isRegistration
                        ? configurationService.getCodeMaxRetriesRegistration()
                        : configurationService.getCodeMaxRetries();

        switch (mfaMethodType) {
            case AUTH_APP:
                return Optional.of(
                        new AuthAppCodeValidator(
                                emailAddress,
                                codeStorageService,
                                configurationService,
                                authenticationService,
                                codeMaxRetries));
            case SMS:
                return Optional.of(
                        new SMSCodeValidator(
                                emailAddress,
                                codeStorageService,
                                authenticationService,
                                codeMaxRetries));
            default:
                return Optional.empty();
        }
    }
}
