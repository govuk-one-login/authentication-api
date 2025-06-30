package uk.gov.di.authentication.frontendapi.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PhoneNumberRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
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
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
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
            AuthenticationService authenticationService,
            AuditService auditService,
            DynamoAccountModifiersService dynamoAccountModifiersService,
            MFAMethodsService mfaMethodsService) {
        super(
                userContext,
                codeStorageService,
                configurationService.getCodeMaxRetries(),
                authenticationService,
                auditService,
                dynamoAccountModifiersService,
                mfaMethodsService);
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
            AuthenticationService authenticationService,
            AuditService auditService,
            DynamoAccountModifiersService dynamoAccountModifiersService,
            AwsSqsClient sqsClient,
            MFAMethodsService mfaMethodsService) {
        super(
                userContext,
                codeStorageService,
                configurationService.getCodeMaxRetries(),
                authenticationService,
                auditService,
                dynamoAccountModifiersService,
                mfaMethodsService);
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

        // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
        var deprecatedCodeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(
                        notificationType.getMfaMethodType(), journeyType);
        if (isCodeBlockedForSession(CODE_BLOCKED_KEY_PREFIX + deprecatedCodeRequestType)) {
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
    public void processSuccessfulCodeRequest(
            String ipAddress, String persistentSessionId, UserProfile userProfile) {
        JourneyType journeyType = codeRequest.getJourneyType();
        if (journeyType != JourneyType.REGISTRATION
                && journeyType != JourneyType.ACCOUNT_RECOVERY) {
            return;
        }

        String phoneNumber =
                PhoneNumberHelper.formatPhoneNumber(codeRequest.getProfileInformation());

        requestPhoneNumberCheck(journeyType, phoneNumber);
        persistPhoneNumber(journeyType, phoneNumber, userProfile);

        AuditService.MetadataPair mfaTypePair = getMfaTypePair(journeyType);

        submitAuditEvent(
                FrontendAuditableEvent.AUTH_UPDATE_PROFILE_PHONE_NUMBER,
                MFAMethodType.SMS,
                phoneNumber,
                ipAddress,
                persistentSessionId,
                journeyType == JourneyType.ACCOUNT_RECOVERY,
                mfaTypePair,
                AuditService.MetadataPair.pair("journey-type", journeyType));
    }

    private void requestPhoneNumberCheck(JourneyType journeyType, String phoneNumber) {
        if (isValidTestNumberForEnvironment(phoneNumber)) {
            LOG.info(
                    "Phone number not submitted for checking as smoke test client and test number");
        } else {
            LOG.info("Sending number to phone check sqs queue");
            submitRequestToExperianPhoneCheckSQSQueue(journeyType, phoneNumber);
        }
    }

    private void persistPhoneNumber(
            JourneyType journeyType, String phoneNumber, UserProfile userProfile) {
        if (journeyType == JourneyType.REGISTRATION) {
            authenticationService.updatePhoneNumberAndAccountVerifiedStatus(
                    emailAddress, phoneNumber, true, true);
        } else {
            if (userProfile.isMfaMethodsMigrated()) {
                String uuid = UUID.randomUUID().toString();
                var smsMfa =
                        MFAMethod.smsMfaMethod(
                                true, true, phoneNumber, PriorityIdentifier.DEFAULT, uuid);

                mfaMethodsService.deleteMigratedMFAsAndCreateNewDefault(
                        userProfile.getEmail(), smsMfa);

            } else {
                authenticationService.setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(
                        emailAddress, phoneNumber);
            }
        }
    }

    private AuditService.MetadataPair getMfaTypePair(JourneyType journeyType) {
        if (journeyType != JourneyType.ACCOUNT_RECOVERY) {
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        Optional<UserProfile> userProfileOpt = userContext.getUserProfile();
        if (userProfileOpt.isEmpty()) {
            LOG.error("Database Corruption: User does not have UserProfile in the UserContext.");
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        UserProfile userProfile = userProfileOpt.get();
        if (!userProfile.isMfaMethodsMigrated()) {
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        return getMfaPriorityForMigratedUser();
    }

    private AuditService.MetadataPair getMfaPriorityForMigratedUser() {
        var maybeUserCredentials = userContext.getUserCredentials();

        if (maybeUserCredentials.isEmpty()) {
            LOG.error(
                    "Database Corruption: User does not have UserCredentials in the UserContext.");
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        var userCredentials = maybeUserCredentials.get();

        var mfaMethods = userCredentials.getMfaMethods();

        if (mfaMethods == null || mfaMethods.isEmpty()) {
            LOG.error(
                    "Data Corruption: Migrated user does not have MFA Methods in the UserCredentials.");
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        String phoneNumberOtpSentTo = codeRequest.getProfileInformation();
        var mfa =
                mfaMethods.stream()
                        .filter(
                                m ->
                                        m.getMfaMethodType()
                                                .equalsIgnoreCase(MFAMethodType.SMS.name()))
                        .filter(m -> m.getDestination().equals(phoneNumberOtpSentTo))
                        .findFirst();

        if (mfa.isEmpty()) {
            LOG.error("Data Corruption: User does not have SMS MFA Method in the UserContext.");
            return AuditService.MetadataPair.pair(
                    AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT.name());
        }

        return AuditService.MetadataPair.pair(
                AUDIT_EVENT_EXTENSIONS_MFA_METHOD, mfa.get().getPriority());
    }

    private void submitRequestToExperianPhoneCheckSQSQueue(
            JourneyType journeyType, String phoneNumber) {
        Optional<UserProfile> userProfileOpt = userContext.getUserProfile();
        if (userProfileOpt.isEmpty()) {
            LOG.error("Database Corruption: User does not have UserProfile in the UserContext.");
            return;
        }

        UserProfile userProfile = userProfileOpt.get();
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
        AuthSessionItem authSession = userContext.getAuthSession();
        return ValidationHelper.isValidTestNumberForEnvironment(
                phoneNumber,
                configurationService.getEnvironment(),
                authSession != null && authSession.getIsSmokeTest());
    }
}
