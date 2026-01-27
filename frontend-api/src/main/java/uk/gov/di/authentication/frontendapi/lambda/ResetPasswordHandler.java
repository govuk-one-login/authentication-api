package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordCompletionRequest;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.shared.validation.PasswordValidator;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_INTERVENTION_COMPLETE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;

public class ResetPasswordHandler extends BaseFrontendHandler<ResetPasswordCompletionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final CommonPasswordsService commonPasswordsService;
    private final PasswordValidator passwordValidator;
    private final DynamoAccountModifiersService dynamoAccountModifiersService;
    private final PermissionDecisionManager permissionDecisionManager;
    private final UserActionsManager userActionsManager;
    private final TestUserHelper testUserHelper;

    private static final Logger LOG = LogManager.getLogger(ResetPasswordHandler.class);

    public ResetPasswordHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            AuditService auditService,
            CommonPasswordsService commonPasswordsService,
            PasswordValidator passwordValidator,
            DynamoAccountModifiersService dynamoAccountModifiersService,
            AuthSessionService authSessionService,
            PermissionDecisionManager permissionDecisionManager,
            UserActionsManager userActionsManager,
            TestUserHelper testUserHelper) {
        super(
                ResetPasswordCompletionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.commonPasswordsService = commonPasswordsService;
        this.passwordValidator = passwordValidator;
        this.dynamoAccountModifiersService = dynamoAccountModifiersService;
        this.permissionDecisionManager = permissionDecisionManager;
        this.userActionsManager = userActionsManager;
        this.testUserHelper = testUserHelper;
    }

    public ResetPasswordHandler() {
        this(ConfigurationService.getInstance());
    }

    public ResetPasswordHandler(ConfigurationService configurationService) {
        super(ResetPasswordCompletionRequest.class, configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.passwordValidator = new PasswordValidator(commonPasswordsService);
        this.dynamoAccountModifiersService =
                new DynamoAccountModifiersService(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
        this.userActionsManager = new UserActionsManager(configurationService);
        this.testUserHelper = new TestUserHelper(configurationService);
    }

    public ResetPasswordHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(ResetPasswordCompletionRequest.class, configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService = new CodeStorageService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.passwordValidator = new PasswordValidator(commonPasswordsService);
        this.dynamoAccountModifiersService =
                new DynamoAccountModifiersService(configurationService);
        this.permissionDecisionManager = new PermissionDecisionManager(configurationService);
        this.userActionsManager = new UserActionsManager(configurationService);
        this.testUserHelper = new TestUserHelper(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            ResetPasswordCompletionRequest request,
            UserContext userContext) {
        LOG.info("Request received to ResetPasswordHandler");

        Optional<ErrorResponse> passwordValidationError =
                passwordValidator.validate(request.password());

        if (passwordValidationError.isPresent()) {
            LOG.info("Error message: {}", passwordValidationError.get().getMessage());
            return generateApiGatewayProxyErrorResponse(400, passwordValidationError.get());
        }
        var userCredentials =
                authenticationService.getUserCredentialsFromEmail(
                        userContext.getAuthSession().getEmailAddress());

        if (Objects.nonNull(userCredentials.getPassword())) {
            if (verifyPassword(userCredentials.getPassword(), request.password())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.NEW_PW_MATCHES_OLD);
            }
        } else {
            LOG.info("Resetting password for migrated user");
        }
        authenticationService.updatePassword(userCredentials.getEmail(), request.password());
        var userProfile =
                authenticationService.getUserProfileByEmail(
                        userContext.getAuthSession().getEmailAddress());

        authSessionService.updateSession(
                userContext
                        .getAuthSession()
                        .withResetPasswordState(AuthSessionItem.ResetPasswordState.SUCCEEDED));

        LOG.info("Calculating internal common subject identifier");
        var internalCommonSubjectId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);

        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        internalCommonSubjectId.getValue(),
                        userCredentials.getEmail(),
                        IpAddressHelper.extractIpAddress(input),
                        userContext
                                .getUserProfile()
                                .map(UserProfile::getPhoneNumber)
                                .orElse(AuditService.UNKNOWN),
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        updateAccountRecoveryBlockTable(
                userProfile, userCredentials, internalCommonSubjectId, auditContext, request);

        PermissionContext permissionContext =
                PermissionContext.builder().withEmailAddress(userCredentials.getEmail()).build();

        userActionsManager.passwordReset(JourneyType.PASSWORD_RESET, permissionContext);

        AuditableEvent auditableEvent;
        if (testUserHelper.isTestJourney(userContext)) {
            auditableEvent = FrontendAuditableEvent.AUTH_PASSWORD_RESET_SUCCESSFUL_FOR_TEST_CLIENT;
        } else {
            var emailNotifyRequest =
                    new NotifyRequest(
                            userCredentials.getEmail(),
                            NotificationType.PASSWORD_RESET_CONFIRMATION,
                            userContext.getUserLanguage(),
                            userContext.getAuthSession().getSessionId(),
                            userContext.getClientSessionId());
            auditableEvent = FrontendAuditableEvent.AUTH_PASSWORD_RESET_SUCCESSFUL;
            LOG.info("Placing message on queue to send password reset confirmation to Email");
            sqsClient.send(serialiseRequest(emailNotifyRequest));
            LOG.info(
                    "{} EMAIL placed on queue with reference: {}",
                    emailNotifyRequest.getNotificationType(),
                    emailNotifyRequest.getUniqueNotificationReference());
            if (shouldSendConfirmationToSms(userProfile)) {
                var smsNotifyRequest =
                        new NotifyRequest(
                                userProfile.getPhoneNumber(),
                                NotificationType.PASSWORD_RESET_CONFIRMATION_SMS,
                                userContext.getUserLanguage(),
                                userContext.getAuthSession().getSessionId(),
                                userContext.getClientSessionId());
                sqsClient.send(serialiseRequest(smsNotifyRequest));
                LOG.info(
                        "{} SMS placed on queue with reference: {}",
                        smsNotifyRequest.getNotificationType(),
                        smsNotifyRequest.getUniqueNotificationReference());
            }
        }

        if (request.isForcedPasswordReset()) {
            auditService.submitAuditEvent(AUTH_PASSWORD_RESET_INTERVENTION_COMPLETE, auditContext);
        }
        auditService.submitAuditEvent(auditableEvent, auditContext);

        LOG.info("Generating successful response");
        return generateEmptySuccessApiGatewayResponse();
    }

    private String serialiseRequest(NotifyRequest request) {
        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonException e) {
            LOG.error("Unable to serialize NotifyRequest");
            throw new RuntimeException("Unable to serialize NotifyRequest");
        }
    }

    private boolean shouldSendConfirmationToSms(UserProfile userProfile) {
        return Objects.nonNull(userProfile.getPhoneNumber()) && userProfile.isPhoneNumberVerified();
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }

    private void updateAccountRecoveryBlockTable(
            UserProfile userProfile,
            UserCredentials userCredentials,
            Subject internalCommonSubjectId,
            AuditContext auditContext,
            ResetPasswordCompletionRequest request) {
        var authAppVerified =
                Optional.ofNullable(userCredentials.getMfaMethods())
                        .orElseGet(Collections::emptyList)
                        .stream()
                        .anyMatch(
                                t ->
                                        t.getMfaMethodType()
                                                        .equals(MFAMethodType.AUTH_APP.getValue())
                                                && t.isMethodVerified());
        var phoneNumberVerified = userProfile.isPhoneNumberVerified();
        LOG.info(
                "AuthAppVerified: {}. PhoneNumberVerified: {}",
                authAppVerified,
                phoneNumberVerified);
        if (!request.allowMfaResetAfterPasswordReset()
                && (phoneNumberVerified || authAppVerified)) {
            LOG.info("Adding block to account modifiers table");
            dynamoAccountModifiersService.setAccountRecoveryBlock(
                    internalCommonSubjectId.getValue(), true);

            auditService.submitAuditEvent(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, auditContext);
        }
    }
}
