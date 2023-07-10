package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordRequest;
import uk.gov.di.authentication.frontendapi.exceptions.SerializationException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
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
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PASSWORD_RESET_REQUESTED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT;
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

    public ResetPasswordRequestHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeGeneratorService codeGeneratorService,
            CodeStorageService codeStorageService,
            AuditService auditService) {
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
        this.codeStorageService = new CodeStorageService(configurationService);
        this.auditService = new AuditService(configurationService);
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
            var isTestClient =
                    TestClientHelper.isTestClientWithAllowedEmail(
                            userContext, configurationService);
            auditService.submitAuditEvent(
                    isTestClient
                            ? PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT
                            : PASSWORD_RESET_REQUESTED,
                    userContext.getClientSessionId(),
                    userContext.getSession().getSessionId(),
                    userContext
                            .getClient()
                            .map(ClientRegistry::getClientID)
                            .orElse(AuditService.UNKNOWN),
                    AuditService.UNKNOWN,
                    request.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    authenticationService.getPhoneNumber(request.getEmail()).orElse(null),
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            return validatePasswordResetCount(request.getEmail(), userContext)
                    .map(t -> generateApiGatewayProxyErrorResponse(400, t))
                    .orElseGet(
                            () -> processPasswordResetRequest(request, userContext, isTestClient));
        } catch (SdkClientException ex) {
            LOG.error("Error sending message to queue", ex);
            return generateApiGatewayProxyResponse(500, "Error sending message to queue");
        } catch (ClientNotFoundException e) {
            LOG.warn("Client not found");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        }
    }

    private APIGatewayProxyResponseEvent processPasswordResetRequest(
            ResetPasswordRequest resetPasswordRequest,
            UserContext userContext,
            boolean isTestClient) {
        var code =
                codeStorageService
                        .getOtpCode(resetPasswordRequest.getEmail(), RESET_PASSWORD_WITH_CODE)
                        .orElseGet(
                                () -> {
                                    var newCode = codeGeneratorService.sixDigitCode();
                                    codeStorageService.saveOtpCode(
                                            resetPasswordRequest.getEmail(),
                                            newCode,
                                            configurationService.getDefaultOtpCodeExpiry(),
                                            RESET_PASSWORD_WITH_CODE);
                                    return newCode;
                                });
        sessionService.save(userContext.getSession().incrementPasswordResetCount());

        if (isTestClient) {
            LOG.info("User is a TestClient so will NOT place message on queue");
        } else {
            LOG.info("Placing message on queue");
            var notifyRequest =
                    new NotifyRequest(
                            resetPasswordRequest.getEmail(),
                            RESET_PASSWORD_WITH_CODE,
                            code,
                            userContext.getUserLanguage());
            sqsClient.send(serialiseNotifyRequest(notifyRequest));
        }
        LOG.info("Successfully processed request");
        return generateEmptySuccessApiGatewayResponse();
    }

    private Optional<ErrorResponse> validatePasswordResetCount(
            String email, UserContext userContext) {
        LOG.info("Validating Password Reset Count");
        if (codeStorageService.isBlockedForEmail(email, PASSWORD_RESET_BLOCKED_KEY_PREFIX)) {
            LOG.info("Code is blocked for email as user has requested too many OTPs");
            return Optional.of(ErrorResponse.ERROR_1023);
        } else if (userContext.getSession().getPasswordResetCount()
                >= configurationService.getCodeMaxRetries()) {
            LOG.info("Setting block for email as user has requested too many OTPs");
            codeStorageService.saveBlockedForEmail(
                    userContext.getSession().getEmailAddress(),
                    PASSWORD_RESET_BLOCKED_KEY_PREFIX,
                    configurationService.getBlockedEmailDuration());
            sessionService.save(userContext.getSession().resetPasswordResetCount());
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        return Optional.empty();
    }

    private String serialiseNotifyRequest(Object request) {
        try {
            return objectMapper.writeValueAsString(request);
        } catch (JsonException e) {
            LOG.error("Unexpected exception when serializing Notify request");
            throw new SerializationException(
                    "Unexpected exception when serializing Notify request");
        }
    }
}
