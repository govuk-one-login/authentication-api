package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.RemoveAccountRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class RemoveAccountHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(RemoveAccountHandler.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;
    private final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    public RemoveAccountHandler(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            AuditService auditService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
    }

    public RemoveAccountHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.auditService = new AuditService(configurationService);
    }

    public RemoveAccountHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall("account-management-api::" + getClass().getSimpleName(), () -> removeAccountRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent removeAccountRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            try {
                                String sessionId =
                                        RequestHeaderHelper.getHeaderValueOrElse(
                                                input.getHeaders(), SESSION_ID_HEADER, "");
                                attachSessionIdToLogs(sessionId);
                                LOG.info("RemoveAccountHandler received request");
                                RemoveAccountRequest removeAccountRequest =
                                        objectMapper.readValue(
                                                input.getBody(), RemoveAccountRequest.class);

                                String email = removeAccountRequest.getEmail();

                                UserProfile userProfile =
                                        authenticationService
                                                .getUserProfileByEmailMaybe(email)
                                                .orElseThrow(
                                                        () ->
                                                                new RuntimeException(
                                                                        "User not found"));

                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();
                                RequestBodyHelper.validatePrincipal(
                                        new Subject(userProfile.getPublicSubjectID()),
                                        authorizerParams);

                                authenticationService.removeAccount(email);
                                LOG.info("User account removed. Adding message to SQS queue");

                                NotifyRequest notifyRequest =
                                        new NotifyRequest(email, NotificationType.DELETE_ACCOUNT);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
                                LOG.info(
                                        "Remove account message successfully added to queue. Generating successful gateway response");
                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.DELETE_ACCOUNT,
                                        context.getAwsRequestId(),
                                        sessionId,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        userProfile.getPhoneNumber(),
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonProcessingException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
