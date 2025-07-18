package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.RemoveAccountRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.DynamoDeleteService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class RemoveAccountHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(RemoveAccountHandler.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final DynamoDeleteService dynamoDeleteService;
    private final AccountDeletionService accountDeletionService;
    private final Json objectMapper = SerializationService.getInstance();

    public RemoveAccountHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            AuditService auditService,
            ConfigurationService configurationService,
            DynamoDeleteService dynamoDeleteService,
            AccountDeletionService accountDeletionService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.configurationService = configurationService;
        this.dynamoDeleteService = dynamoDeleteService;
        this.accountDeletionService = accountDeletionService;
    }

    public RemoveAccountHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.auditService = new AuditService(configurationService);
        this.configurationService = configurationService;
        this.dynamoDeleteService = new DynamoDeleteService(configurationService);
        this.accountDeletionService =
                new AccountDeletionService(
                        authenticationService,
                        sqsClient,
                        auditService,
                        configurationService,
                        dynamoDeleteService);
    }

    public RemoveAccountHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> removeAccountRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent removeAccountRequestHandler(
            APIGatewayProxyRequestEvent input) {
        try {
            String sessionId =
                    RequestHeaderHelper.getHeaderValueOrElse(
                            input.getHeaders(), SESSION_ID_HEADER, "");
            attachTraceId();
            attachSessionIdToLogs(sessionId);
            LOG.info("RemoveAccountHandler received request");
            RemoveAccountRequest removeAccountRequest =
                    objectMapper.readValue(input.getBody(), RemoveAccountRequest.class);

            String email = removeAccountRequest.getEmail();
            var userProfile =
                    authenticationService
                            .getUserProfileByEmailMaybe(email)
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            authoriseRequest(input, userProfile);

            accountDeletionService.removeAccount(
                    Optional.of(input),
                    userProfile,
                    AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                    AccountDeletionReason.USER_INITIATED);

            return generateEmptySuccessApiGatewayResponse();
        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ACCT_DOES_NOT_EXIST);
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }

    private void authoriseRequest(APIGatewayProxyRequestEvent input, UserProfile userProfile) {
        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                authenticationService,
                authorizerParams)) {
            throw new InvalidPrincipalException("Invalid Principal in request");
        }
    }
}
