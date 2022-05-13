package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.services.ResetPasswordService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1001;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.CodeStorageService.PASSWORD_RESET_BLOCKED_KEY_PREFIX;

public class ResetPasswordRequestHandler extends BaseFrontendHandler<ResetPasswordRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(ResetPasswordRequestHandler.class);

    private final AwsSqsClient sqsClient;
    private final CodeGeneratorService codeGeneratorService;
    private final CodeStorageService codeStorageService;
    private final AuditService auditService;
    private final ResetPasswordService resetPasswordService;

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuditService auditService,
            ResetPasswordService resetPasswordService) {
        super(
                ResetPasswordRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.sqsClient = sqsClient;
        this.codeGeneratorService = codeGeneratorService;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.resetPasswordService = resetPasswordService;
    }

    public ResetPasswordRequestHandler() {
        this(ConfigurationService.getInstance());
    }

    public ResetPasswordRequestHandler(ConfigurationService configurationService) {
        super(ResetPasswordRequest.class, configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeGeneratorService = new CodeGeneratorService();
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.resetPasswordService = new ResetPasswordService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            ResetPasswordRequest request,
            UserContext userContext) {
        attachSessionIdToLogs(userContext.getSession().getSessionId());

        LOG.info("Processing request");
        try {
            if (!userContext.getSession().validateSession(request.getEmail())) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
            }
            String persistentSessionId =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.PASSWORD_RESET_REQUESTED,
                    context.getAwsRequestId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    request.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    persistentSessionId);

            Optional<ErrorResponse> errorResponse =
                    validatePasswordResetCount(request.getEmail(), userContext);
            if (errorResponse.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            return processPasswordResetRequest(request, userContext, persistentSessionId);

        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ERROR_1001);
        }
    }

    private APIGatewayProxyResponseEvent processPasswordResetRequest(
            ResetPasswordRequest resetPasswordRequest,
            UserContext userContext,
            String persistentSessionId)
            throws JsonException {
        String subjectId =
                authenticationService
                        .getSubjectFromEmail(resetPasswordRequest.getEmail())
                        .getValue();
        String code;
        String notifyText;
        NotificationType notificationType;
        if (resetPasswordRequest.isUseCodeFlow()) {
            code = codeGeneratorService.sixDigitCode();
            notifyText = code;
            notificationType = RESET_PASSWORD_WITH_CODE;
            codeStorageService.saveOtpCode(
                    resetPasswordRequest.getEmail(),
                    code,
                    configurationService.getCodeExpiry(),
                    notificationType);
        } else {
            code = codeGeneratorService.twentyByteEncodedRandomCode();
            notifyText =
                    resetPasswordService.buildResetPasswordLink(
                            code, userContext.getSession().getSessionId(), persistentSessionId);
            notificationType = RESET_PASSWORD;
            codeStorageService.savePasswordResetCode(
                    subjectId, code, configurationService.getCodeExpiry(), notificationType);
        }
        NotifyRequest notifyRequest =
                new NotifyRequest(resetPasswordRequest.getEmail(), notificationType, notifyText);
        sessionService.save(userContext.getSession().incrementPasswordResetCount());
        sqsClient.send(serialiseRequest(notifyRequest));
        LOG.info("Successfully processed request");
        return generateEmptySuccessApiGatewayResponse();
    }

    private Optional<ErrorResponse> validatePasswordResetCount(
            String email, UserContext userContext) {
        if (codeStorageService.isBlockedForEmail(email, PASSWORD_RESET_BLOCKED_KEY_PREFIX)) {
            return Optional.of(ErrorResponse.ERROR_1023);
        } else if (userContext.getSession().getPasswordResetCount()
                >= configurationService.getCodeMaxRetries()) {
            codeStorageService.saveBlockedForEmail(
                    userContext.getSession().getEmailAddress(),
                    PASSWORD_RESET_BLOCKED_KEY_PREFIX,
                    configurationService.getBlockedEmailDuration());
            sessionService.save(userContext.getSession().resetPasswordResetCount());
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        return Optional.empty();
    }

    private String serialiseRequest(Object request) throws JsonException {
        return objectMapper.writeValueAsString(request);
    }
}
