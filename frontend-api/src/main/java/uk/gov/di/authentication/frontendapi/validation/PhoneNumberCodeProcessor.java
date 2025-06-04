package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PhoneNumberRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
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
        JourneyType journeyType = codeRequest.getJourneyType();
        if (journeyType.equals(JourneyType.SIGN_IN)) {
            LOG.error("Sign In Phone number codes are not supported");
            throw new RuntimeException("Sign In Phone number codes are not supported");
        }
        var notificationType =
                List.of(JourneyType.PASSWORD_RESET_MFA, JourneyType.REAUTHENTICATION)
                                .contains(journeyType)
                        ? NotificationType.MFA_SMS
                        : NotificationType.VERIFY_PHONE_NUMBER;

        var codeRequestType = CodeRequestType.getCodeRequestType(notificationType, journeyType);
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

        var formattedPhoneNumber =
                PhoneNumberHelper.formatPhoneNumber(codeRequest.getProfileInformation());
        String codeIdentifier = emailAddress.concat(formattedPhoneNumber);
        var storedCode =
                isTestClient
                        ? configurationService.getTestClientVerifyPhoneNumberOTP()
                        : codeStorageService.getOtpCode(codeIdentifier, notificationType);

        var errorResponse =
                ValidationHelper.validateVerificationCode(
                        notificationType,
                        journeyType,
                        storedCode,
                        codeRequest.getCode(),
                        codeStorageService,
                        emailAddress,
                        configurationService);

        if (errorResponse.isEmpty()) {
            codeStorageService.deleteOtpCode(codeIdentifier, notificationType);
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

            if (isValidTestNumberForEnvironment(phoneNumber)) {
                LOG.info(
                        "Phone number not submitted for checking as smoke test client and test number");
            } else {
                LOG.info("Sending number to phone check sqs queue");
                submitRequestToExperianPhoneCheckSQSQueue(journeyType, phoneNumber);
            }

            switch (journeyType) {
                case REGISTRATION -> dynamoService.updatePhoneNumberAndAccountVerifiedStatus(
                        emailAddress, phoneNumber, true, true);
                case ACCOUNT_RECOVERY -> dynamoService
                        .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(emailAddress, phoneNumber);
            }

            submitAuditEvent(
                    FrontendAuditableEvent.AUTH_UPDATE_PROFILE_PHONE_NUMBER,
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
            AuthSessionItem authSession = userContext.getAuthSession();
            String internalCommonSubjectIdentifier =
                    authSession != null ? authSession.getInternalCommonSubjectId() : "";

            var phoneNumberRequest =
                    new PhoneNumberRequest(
                            phoneNumberVerified,
                            phoneNumber,
                            updatedPhoneNumber,
                            journeyType,
                            internalCommonSubjectIdentifier);
            try {
                sqsClient.send(objectMapper.writeValueAsString(phoneNumberRequest));
                LOG.info("Message successfully sent to Experian phone check SQS queue");
            } catch (Exception e) {
                LOG.error(
                        "Unexpected exception when writing phone number request to experian checker SQS queue: {}",
                        e.getMessage());
            }
        }
    }

    private boolean isValidTestNumberForEnvironment(String phoneNumber) {
        boolean isSmokeTestClient =
                userContext.getClient().map(ClientRegistry::isSmokeTest).orElse(false);
        LOG.info(
                "isSmokeTest on auth session equal to client registry? {}",
                userContext.getAuthSession().getIsSmokeTest() == isSmokeTestClient);
        return ValidationHelper.isValidTestNumberForEnvironment(
                phoneNumber, configurationService.getEnvironment(), isSmokeTestClient);
    }
}
