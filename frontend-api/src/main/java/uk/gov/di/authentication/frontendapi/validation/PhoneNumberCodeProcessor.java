package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PhoneNumberRequest;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.ValidationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.TestClientHelper.isTestClientWithAllowedEmail;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class PhoneNumberCodeProcessor extends MfaCodeProcessor {

    private final ConfigurationService configurationService;
    private final UserContext userContext;
    private final CodeRequest codeRequest;
    private final AwsSqsClient sqsClient;
    private final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(PhoneNumberCodeProcessor.class);

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
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getExperianPhoneCheckerQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    PhoneNumberCodeProcessor(
            CodeStorageService codeStorageService,
            UserContext userContext,
            ConfigurationService configurationService,
            CodeRequest codeRequest,
            AuthenticationService dynamoService,
            AuditService auditService,
            DynamoAccountModifiersService dynamoAccountModifiersService,
            AwsSqsClient sqsClient) {
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
        this.sqsClient = sqsClient;
    }

    @Override
    public Optional<ErrorResponse> validateCode() {
        if (codeRequest.getJourneyType().equals(JourneyType.SIGN_IN)) {
            LOG.error("Sign In Phone number codes are not supported");
            throw new RuntimeException("Sign In Phone number codes are not supported");
        }
        var notificationType =
                List.of(JourneyType.PASSWORD_RESET_MFA, JourneyType.REAUTHENTICATION)
                                .contains(codeRequest.getJourneyType())
                        ? NotificationType.MFA_SMS
                        : NotificationType.VERIFY_PHONE_NUMBER;

        var codeRequestType =
                CodeRequestType.getCodeRequestType(notificationType, codeRequest.getJourneyType());
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        if (isCodeBlockedForSession(codeBlockedKeyPrefix)) {
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

        var errorResponse =
                ValidationHelper.validateVerificationCode(
                        notificationType,
                        codeRequest.getJourneyType(),
                        storedCode,
                        codeRequest.getCode(),
                        codeStorageService,
                        emailAddress,
                        configurationService);

        if (errorResponse.isEmpty()) {
            codeStorageService.deleteOtpCode(emailAddress, notificationType);
        }

        return errorResponse;
    }

    @Override
    public void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId) {
        JourneyType journeyType = codeRequest.getJourneyType();
        if (journeyType == JourneyType.REGISTRATION
                || journeyType == JourneyType.ACCOUNT_RECOVERY) {
            String phoneNumber =
                    PhoneNumberHelper.formatPhoneNumber(codeRequest.getProfileInformation());

            submitRequestToExperianPhoneCheckSQSQueue(journeyType, phoneNumber);

            switch (journeyType) {
                case REGISTRATION -> dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                        emailAddress, phoneNumber, true, true);
                case ACCOUNT_RECOVERY -> dynamoService
                        .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(emailAddress, phoneNumber);
            }

            submitAuditEvent(
                    FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                    MFAMethodType.SMS,
                    phoneNumber,
                    ipAddress,
                    persistentSessionId,
                    journeyType == JourneyType.ACCOUNT_RECOVERY);
        }
    }

    private void submitRequestToExperianPhoneCheckSQSQueue(
            JourneyType journeyType, String phoneNumber) {
        UserProfile userProfile = userContext.getUserProfile().get();
        boolean phoneNumberVerified = userProfile.isPhoneNumberVerified();
        boolean updatedPhoneNumber = !phoneNumber.equals(userProfile.getPhoneNumber());

        if (configurationService.isPhoneCheckerWithReplyEnabled()
                && (journeyType != JourneyType.ACCOUNT_RECOVERY || updatedPhoneNumber)) {
            Session session = userContext.getSession();
            String internalCommonSubjectIdentifier =
                    session != null ? session.getInternalCommonSubjectIdentifier() : "";

            var phoneNumberRequest =
                    new PhoneNumberRequest(
                            phoneNumberVerified,
                            phoneNumber,
                            updatedPhoneNumber,
                            journeyType,
                            internalCommonSubjectIdentifier);
            try {
                sqsClient.send(objectMapper.writeValueAsString(phoneNumberRequest));
            } catch (Exception e) {
                LOG.error(
                        "Unexpected exception when writing phone number request to experian checker SQS queue: {}",
                        e.getMessage());
            }
        }
    }
}
