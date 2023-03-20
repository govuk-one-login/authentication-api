package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordCompletionRequest;
import uk.gov.di.authentication.frontendapi.services.DynamoAccountRecoveryBlockService;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.TestClientHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

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
    private final DynamoAccountRecoveryBlockService accountRecoveryBlockService;

    private static final Logger LOG = LogManager.getLogger(ResetPasswordHandler.class);

    public ResetPasswordHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuditService auditService,
            CommonPasswordsService commonPasswordsService,
            PasswordValidator passwordValidator,
            DynamoAccountRecoveryBlockService accountRecoveryBlockService) {
        super(
                ResetPasswordCompletionRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.commonPasswordsService = commonPasswordsService;
        this.passwordValidator = passwordValidator;
        this.accountRecoveryBlockService = accountRecoveryBlockService;
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
        this.accountRecoveryBlockService =
                new DynamoAccountRecoveryBlockService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            ResetPasswordCompletionRequest request,
            UserContext userContext) {
        LOG.info("Request received to ResetPasswordHandler");
        try {
            Optional<ErrorResponse> passwordValidationError =
                    passwordValidator.validate(request.getPassword());

            if (passwordValidationError.isPresent()) {
                LOG.info("Error message: {}", passwordValidationError.get().getMessage());
                return generateApiGatewayProxyErrorResponse(400, passwordValidationError.get());
            }
            var userCredentials =
                    authenticationService.getUserCredentialsFromEmail(
                            userContext.getSession().getEmailAddress());

            if (Objects.nonNull(userCredentials.getPassword())) {
                if (verifyPassword(userCredentials.getPassword(), request.getPassword())) {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1024);
                }
            } else {
                LOG.info("Resetting password for migrated user");
            }
            authenticationService.updatePassword(userCredentials.getEmail(), request.getPassword());
            var userProfile =
                    authenticationService.getUserProfileByEmail(
                            userContext.getSession().getEmailAddress());

            updateAccountRecoveryBlockTable(
                    configurationService.isAccountRecoveryBlockEnabled(),
                    userProfile,
                    userCredentials);

            var incorrectPasswordCount =
                    codeStorageService.getIncorrectPasswordCount(userCredentials.getEmail());
            if (incorrectPasswordCount != 0) {
                codeStorageService.deleteIncorrectPasswordCount(userCredentials.getEmail());
            }
            AuditableEvent auditableEvent;
            if (TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService)) {
                auditableEvent = FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL_FOR_TEST_CLIENT;
            } else {
                var emailNotifyRequest =
                        new NotifyRequest(
                                userCredentials.getEmail(),
                                NotificationType.PASSWORD_RESET_CONFIRMATION,
                                userContext.getUserLanguage());
                auditableEvent = FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL;
                LOG.info("Placing message on queue to send password reset confirmation to Email");
                sqsClient.send(serialiseRequest(emailNotifyRequest));
                if (shouldSendConfirmationToSms(userProfile, configurationService)) {
                    var smsNotifyRequest =
                            new NotifyRequest(
                                    userProfile.getPhoneNumber(),
                                    NotificationType.PASSWORD_RESET_CONFIRMATION_SMS,
                                    userContext.getUserLanguage());
                    LOG.info("Placing message on queue to send password reset confirmation to SMS");
                    sqsClient.send(serialiseRequest(smsNotifyRequest));
                }
            }
            auditService.submitAuditEvent(
                    auditableEvent,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    userCredentials.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
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

    private boolean shouldSendConfirmationToSms(
            UserProfile userProfile, ConfigurationService configurationService) {
        return Objects.nonNull(userProfile.getPhoneNumber())
                && userProfile.isPhoneNumberVerified()
                && configurationService.isResetPasswordConfirmationSmsEnabled();
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }

    private void updateAccountRecoveryBlockTable(
            boolean accountRecoveryBlockEnabled,
            UserProfile userProfile,
            UserCredentials userCredentials) {
        LOG.info("AccountRecoveryBlock enabled: {}", accountRecoveryBlockEnabled);
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
        if (accountRecoveryBlockEnabled && phoneNumberVerified) {
            LOG.info("Adding block with TTL to account recovery table");
            accountRecoveryBlockService.addBlockWithTTL(userProfile.getEmail());
        } else if (accountRecoveryBlockEnabled && authAppVerified) {
            LOG.info("Adding block with NO TTL to account recovery table");
            accountRecoveryBlockService.addBlockWithNoTTL(userProfile.getEmail());
        }
    }
}
