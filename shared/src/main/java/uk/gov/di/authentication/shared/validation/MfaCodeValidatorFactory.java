package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class MfaCodeValidatorFactory {
    private MfaCodeValidatorFactory() {}

    public static Optional<MfaCodeValidator> getMfaCodeValidator(
            MFAMethodType mfaMethodType,
            boolean isRegistration,
            UserContext userContext,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            DynamoService dynamoService) {

        switch (mfaMethodType) {
            case AUTH_APP:
                int codeMaxRetries =
                        isRegistration
                                ? configurationService.getCodeMaxRetriesRegistration()
                                : configurationService.getCodeMaxRetries();
                return Optional.of(
                        new AuthAppCodeValidator(
                                userContext,
                                codeStorageService,
                                configurationService,
                                dynamoService,
                                codeMaxRetries));
            default:
                return Optional.empty();
        }
    }
}
