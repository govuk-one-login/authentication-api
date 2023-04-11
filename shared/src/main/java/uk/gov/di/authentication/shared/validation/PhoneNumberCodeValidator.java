package uk.gov.di.authentication.shared.validation;

import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;

public class PhoneNumberCodeValidator extends MfaCodeValidator {

    private final ConfigurationService configurationService;
    private final UserContext userContext;
    private final boolean isRegistration;

    PhoneNumberCodeValidator(
            CodeStorageService codeStorageService,
            UserContext userContext,
            ConfigurationService configurationService,
            boolean isRegistration) {
        super(
                userContext.getSession().getEmailAddress(),
                codeStorageService,
                configurationService.getCodeMaxRetries());
        this.userContext = userContext;
        this.configurationService = configurationService;
        this.isRegistration = isRegistration;
    }

    @Override
    public Optional<ErrorResponse> validateCode(String code) {
        if (!isRegistration) {
            LOG.error("Sign In Phone number codes are not supported");
            throw new RuntimeException("Sign In Phone number codes are not supported");
        }
        var notificationType =
                isRegistration ? NotificationType.VERIFY_PHONE_NUMBER : NotificationType.MFA_SMS;
        if (isCodeBlockedForSession()) {
            LOG.info("Code blocked for session");
            return Optional.of(ErrorResponse.ERROR_1034);
        }
        boolean isTestClient;
        try {
            isTestClient = isTestClientWithAllowedEmail(userContext, configurationService);
        } catch (ClientNotFoundException e) {
            LOG.error("No client found", e);
            throw new RuntimeException(e);
        }
        var storedCode =
                isTestClient
                        ? configurationService.getTestClientVerifyPhoneNumberOTP()
                        : codeStorageService.getOtpCode(emailAddress, notificationType);

        return ValidationHelper.validateVerificationCode(
                notificationType,
                storedCode,
                code,
                codeStorageService,
                emailAddress,
                configurationService.getCodeMaxRetries());
    }
}
