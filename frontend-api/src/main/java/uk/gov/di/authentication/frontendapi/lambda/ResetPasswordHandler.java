package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ResetPasswordWithCodeRequest;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;

public class ResetPasswordHandler extends BaseFrontendHandler<ResetPasswordWithCodeRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private final ValidationService validationService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private static final Logger LOG = LogManager.getLogger(ResetPasswordHandler.class);

    public ResetPasswordHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            ValidationService validationService,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuditService auditService) {
        super(
                ResetPasswordWithCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.validationService = validationService;
        this.auditService = auditService;
    }

    public ResetPasswordHandler() {
        this(ConfigurationService.getInstance());
    }

    public ResetPasswordHandler(ConfigurationService configurationService) {
        super(ResetPasswordWithCodeRequest.class, configurationService);
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.validationService = new ValidationService();
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            ResetPasswordWithCodeRequest request,
            UserContext userContext) {
        LOG.info("Request received to ResetPasswordHandler");
        try {
            Optional<ErrorResponse> errorResponse =
                    validationService.validatePassword(request.getPassword());
            if (errorResponse.isPresent()) {
                return generateApiGatewayProxyErrorResponse(400, errorResponse.get());
            }
            Optional<String> subject =
                    codeStorageService.getSubjectWithPasswordResetCode(request.getCode());
            if (subject.isEmpty()) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1021);
            }
            UserCredentials userCredentials =
                    authenticationService.getUserCredentialsFromSubject(subject.get());
            if (userCredentials.getPassword() != null) {
                if (verifyPassword(userCredentials.getPassword(), request.getPassword())) {
                    return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1024);
                }
            } else {
                LOG.info("Resetting password for migrated user");
            }
            codeStorageService.deleteSubjectWithPasswordResetCode(request.getCode());
            authenticationService.updatePassword(userCredentials.getEmail(), request.getPassword());

            int incorrectPasswordCount =
                    codeStorageService.getIncorrectPasswordCount(userCredentials.getEmail());
            if (incorrectPasswordCount != 0) {
                codeStorageService.deleteIncorrectPasswordCount(userCredentials.getEmail());
            }

            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            userCredentials.getEmail(),
                            NotificationType.PASSWORD_RESET_CONFIRMATION);
            LOG.info("Placing message on queue");
            sqsClient.send(serialiseRequest(notifyRequest));
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                    context.getAwsRequestId(),
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
        } catch (JsonProcessingException | ConstraintViolationException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        LOG.info("Generating successful response");
        return generateEmptySuccessApiGatewayResponse();
    }

    private String serialiseRequest(Object request) throws JsonProcessingException {
        return objectMapper.writeValueAsString(request);
    }

    private static boolean verifyPassword(String hashedPassword, String password) {
        return Argon2MatcherHelper.matchRawStringWithEncoded(password, hashedPassword);
    }
}
