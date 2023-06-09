package uk.gov.di.authentication.frontendapi.validation;

import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;

public class PhoneNumberCodeProcessor extends MfaCodeProcessor {

    private final ConfigurationService configurationService;
    private final UserContext userContext;
    private final CodeRequest codeRequest;

    PhoneNumberCodeProcessor(
            CodeStorageService codeStorageService,
            UserContext userContext,
            ConfigurationService configurationService,
            CodeRequest codeRequest,
            AuthenticationService dynamoService,
            AuditService auditService,
            DynamoAccountModifiersService dynamoAccountModifiersService) {
        super(
                userContext,
                codeStorageService,
                configurationService.getCodeMaxRetries(),
                dynamoService,
                auditService,
                dynamoAccountModifiersService);
        this.userContext = userContext;
        this.configurationService = configurationService;
        this.codeRequest = codeRequest;
    }

    @Override
    public Optional<ErrorResponse> validateCode() {
        if (codeRequest.getJourneyType().equals(JourneyType.SIGN_IN)) {
            LOG.error("Sign In Phone number codes are not supported");
            throw new RuntimeException("Sign In Phone number codes are not supported");
        }
        var notificationType =
                codeRequest.getJourneyType().equals(JourneyType.SIGN_IN)
                        ? NotificationType.MFA_SMS
                        : NotificationType.VERIFY_PHONE_NUMBER;
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

        if (!storedCode.isPresent()) {
            LOG.info("No stored code returned from the codeStorageService");
        }

        return ValidationHelper.validateVerificationCode(
                notificationType,
                storedCode,
                codeRequest.getCode(),
                codeStorageService,
                emailAddress,
                configurationService.getCodeMaxRetries());
    }

    @Override
    public void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId) {
        switch (codeRequest.getJourneyType()) {
            case REGISTRATION:
                dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                        emailAddress, codeRequest.getProfileInformation(), true, true);
                submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                        MFAMethodType.SMS,
                        codeRequest.getProfileInformation(),
                        ipAddress,
                        persistentSessionId,
                        false);
                break;
            case ACCOUNT_RECOVERY:
                dynamoService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(
                        emailAddress, codeRequest.getProfileInformation());
                submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                        MFAMethodType.SMS,
                        codeRequest.getProfileInformation(),
                        ipAddress,
                        persistentSessionId,
                        true);
                break;
        }
    }
}
