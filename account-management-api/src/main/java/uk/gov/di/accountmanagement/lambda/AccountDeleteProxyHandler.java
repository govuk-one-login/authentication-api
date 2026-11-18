package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.AccountDeleteProxyRequest;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.time.Clock;
import java.util.Optional;

import static uk.gov.di.accountmanagement.helpers.AuditHelper.accountManagementAuditContext;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class AccountDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AccountDeleteProxyHandler.class);
    private final AccountDataApiService accountDataApiService;
    private final StructuredAuditService structuredAuditService;
    private final DynamoService dynamoService;
    private final ConfigurationService configurationService;
    private final Json objectMapper = SerializationService.getInstance();
    private final AwsSqsClient sqsClient;

    public AccountDeleteProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public AccountDeleteProxyHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accountDataApiService = new AccountDataApiService(configurationService);
        this.structuredAuditService = new StructuredAuditService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
    }

    public AccountDeleteProxyHandler(
            ConfigurationService configurationService,
            AccountDataApiService accountDataApiService,
            StructuredAuditService structuredAuditService,
            DynamoService dynamoService,
            AwsSqsClient sqsClient) {
        this.configurationService = configurationService;
        this.accountDataApiService = accountDataApiService;
        this.structuredAuditService = structuredAuditService;
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> accountDeleteProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent accountDeleteProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        attachTraceId();
        LOG.info("AccountDeleteProxyHandler called");

        AccountDeleteProxyRequest request;
        try {
            request =
                    objectMapper.readValue(input.getBody(), AccountDeleteProxyRequest.class, true);
        } catch (JsonException e) {
            LOG.warn("Could not parse account delete proxy request body");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }

        var maybeUserProfile = Optional.<UserProfile>empty();

        var publicSubjectId = input.getPathParameters().getOrDefault("publicSubjectId", "");
        if (publicSubjectId.isEmpty()) {
            LOG.warn("No publicSubjectId in path parameters, request will likely fail");
        } else {
            maybeUserProfile =
                    dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);
        }

        if (maybeUserProfile.isEmpty()) {
            LOG.warn(
                    "No user profile found for account delete request, not proxying request to account data api");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.USER_NOT_FOUND);
        }

        var userProfile = maybeUserProfile.get();

        var token = input.getHeaders().getOrDefault("X-ADAPI-AccessToken", "");
        if (token.isEmpty()) {
            LOG.warn("No X-ADAPI-AccessToken in headers, request will likely fail");
        }

        try {
            var response = accountDataApiService.deleteAccount(publicSubjectId, token);
            if (response.statusCode() == 204) {
                reportAccountDeleted(publicSubjectId, userProfile, request, input);
                sendEmailNotification(userProfile.getEmail(), publicSubjectId);
            }

            return generateApiGatewayProxyResponse(response.statusCode(), response.body());
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.warn("Attempted deleting account but failed due to '{}'", e.getMessage());
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
    }

    private void reportAccountDeleted(
            String publicSubject,
            UserProfile userProfile,
            AccountDeleteProxyRequest request,
            APIGatewayProxyRequestEvent input) {
        var auditContextResult =
                accountManagementAuditContext(
                        configurationService,
                        dynamoService,
                        input,
                        userProfile,
                        request.clientId());
        if (auditContextResult.isFailure()) {
            LOG.warn(
                    "Could not build audit context ({}); skipping AUTH_DELETE_ACCOUNT audit event",
                    auditContextResult.getFailure());
            return;
        }
        var auditContext = auditContextResult.getSuccess();

        var auditEvent =
                AuthDeleteAccount.create(
                        auditContext.withPhoneNumber(userProfile.getPhoneNumber()),
                        publicSubject,
                        userProfile.getLegacySubjectID(),
                        request.reason().name(),
                        Clock.systemUTC());
        structuredAuditService.submitAuditEvent(auditEvent);
    }

    private void sendEmailNotification(String email, String publicSubjectId) {
        var notificationType = NotificationType.ACCOUNT_DELETED_SELF_SERVICE;

        try {
            var notifyRequest = new NotifyRequest(email, notificationType);

            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

            LOG.info(
                    "Notify request sent with notification type '{}' and publicSubjectId '{}'",
                    notificationType,
                    publicSubjectId);
        } catch (Exception e) {
            LOG.error(
                    "Error {} when sending Notify request sent with notification type '{}' and publicSubjectId '{}', account may have been deleted without notification sent",
                    e,
                    notificationType,
                    publicSubjectId);
        }
    }
}
