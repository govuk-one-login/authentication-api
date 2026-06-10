package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.PasskeysDeleteProxyFailureReason;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyDeleteSuccessful;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.http.HttpResponse;
import java.time.Clock;
import java.util.Map;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_PASSKEY_DELETE_FAILED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_PASSKEY_DELETE_SUCCESSFUL;
import static uk.gov.di.accountmanagement.helpers.AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR;
import static uk.gov.di.accountmanagement.helpers.AuditHelper.accountManagementAuditContext;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_RESTRICTED_PASSKEY;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_RESTRICTED_PASSKEY_CREDENTIAL_ID;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class PasskeysDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteProxyHandler.class);
    private final ConfigurationService configurationService;
    private final AccountDataApiService accountDataApiService;
    private final SerializationService serializationService = SerializationService.getInstance();
    private final AwsSqsClient sqsClient;
    private final DynamoService dynamoService;
    private final AuditService auditService;
    private final StructuredAuditService structuredAuditService;

    public PasskeysDeleteProxyHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysDeleteProxyHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accountDataApiService = new AccountDataApiService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.dynamoService = new DynamoService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.structuredAuditService = new StructuredAuditService(configurationService);
    }

    public PasskeysDeleteProxyHandler(
            ConfigurationService configurationService,
            AccountDataApiService accountDataApiService,
            AwsSqsClient sqsClient,
            DynamoService dynamoService,
            AuditService auditService,
            StructuredAuditService structuredAuditService) {
        this.configurationService = configurationService;
        this.accountDataApiService = accountDataApiService;
        this.sqsClient = sqsClient;
        this.dynamoService = dynamoService;
        this.auditService = auditService;
        this.structuredAuditService = structuredAuditService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> passkeyDeleteProxyHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeyDeleteProxyHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysDeleteProxyHandler invoked");

        PasskeysDeleteRequest request = extractPasskeyDeleteRequest(input);

        var userProfileResult = getUserProfile(request.publicSubjectId);
        if (userProfileResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
        var userProfile = userProfileResult.getSuccess();
        var userEmail = userProfile.getEmail();

        var auditContextResult =
                accountManagementAuditContext(
                        configurationService, dynamoService, input, userProfile);
        if (auditContextResult.isFailure()) {
            LOG.error(
                    "Error when building audit context with error code {}. No events raised",
                    auditContextResult.getFailure());
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.FAILED_TO_RAISE_AUDIT_EVENT);
        }
        var auditContext = auditContextResult.getSuccess();

        var currentPasskeyCountResult = getPasskeyCount(request);
        if (currentPasskeyCountResult.isFailure()) {
            emitFailedAuditEvent(auditContext, request);
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
        var currentPasskeyCount = currentPasskeyCountResult.getSuccess();

        var deletePasskeyResponseResult = deletePasskey(request);
        if (deletePasskeyResponseResult.isFailure()) {
            emitFailedAuditEvent(auditContext, request);
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
        HttpResponse<String> deletePasskeyResponse = deletePasskeyResponseResult.getSuccess();

        var deletePasskeyProxyResponse =
                generateApiGatewayProxyResponse(
                        deletePasskeyResponse.statusCode(), deletePasskeyResponse.body());

        if (deletePasskeyResponse.statusCode() != 204) {
            LOG.warn(
                    "Passkey Deleted Email notification not sent because delete passkey response was {} for Public Subject ID {}",
                    deletePasskeyResponse.statusCode(),
                    request.publicSubjectId);
            emitFailedAuditEvent(auditContext, request);
        } else {
            emitSuccessAuditEvent(auditContext, request, currentPasskeyCount);
            sendEmailNotification(request, userEmail, currentPasskeyCount);
        }

        return deletePasskeyProxyResponse;
    }

    private PasskeysDeleteRequest extractPasskeyDeleteRequest(APIGatewayProxyRequestEvent input) {
        var publicSubjectId = input.getPathParameters().getOrDefault("publicSubjectId", "");
        if (publicSubjectId.isEmpty()) {
            LOG.warn("No publicSubjectId in path parameters, request will likely fail");
        }

        var passkeyIdentifier = input.getPathParameters().getOrDefault("passkeyIdentifier", "");
        if (passkeyIdentifier.isEmpty()) {
            LOG.warn("No passkeyIdentifier in path parameters, request will likely fail");
        }

        var token = input.getHeaders().getOrDefault("X-ADAPI-AccessToken", "");
        if (token.isEmpty()) {
            LOG.warn("No X-ADAPI-AccessToken in headers, request will likely fail");
        }

        var userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        return new PasskeysDeleteRequest(publicSubjectId, token, passkeyIdentifier, userLanguage);
    }

    private Result<PasskeysDeleteProxyFailureReason, UserProfile> getUserProfile(
            String publicSubjectId) {
        var userProfile = dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (userProfile.isEmpty()) {
            LOG.warn("No user profile found for public subject ID{}", publicSubjectId);
            return Result.failure(PasskeysDeleteProxyFailureReason.FAILED_TO_FIND_USER_PROFILE);
        }

        return Result.success(userProfile.get());
    }

    private Result<PasskeysDeleteProxyFailureReason, Integer> getPasskeyCount(
            PasskeysDeleteRequest request) {
        try {
            var userPasskeys =
                    accountDataApiService.retrievePasskeys(request.publicSubjectId, request.token);
            return Result.success(userPasskeys.passkeys().size());
        } catch (UnsuccessfulAccountDataApiResponseException | Json.JsonException e) {
            LOG.warn(
                    "Attempted to retrieve passkeys for user with publicSubjectId '{}' but failed due to '{}'",
                    request.publicSubjectId,
                    e.getMessage());
            return Result.failure(
                    PasskeysDeleteProxyFailureReason.FAILED_TO_RETRIEVE_PASSKEY_COUNT);
        }
    }

    private Result<PasskeysDeleteProxyFailureReason, HttpResponse<String>> deletePasskey(
            PasskeysDeleteRequest request) {
        try {
            var response =
                    accountDataApiService.deletePasskey(
                            request.publicSubjectId, request.passkeyId, request.token);
            return Result.success(response);
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.warn(
                    "Attempted to delete passkey with ID '{}' but failed due to '{}'",
                    request.passkeyId,
                    e.getMessage());
            return Result.failure(PasskeysDeleteProxyFailureReason.FAILED_TO_DELETE_PASSKEY);
        }
    }

    private void sendEmailNotification(
            PasskeysDeleteRequest request, String email, int passkeyCount) {
        var passkeyCountPostDelete = passkeyCount - 1;
        var notificationType =
                passkeyCountPostDelete <= 0
                        ? NotificationType.PASSKEY_DELETED_NONE_REMAINING
                        : NotificationType.PASSKEY_DELETED_SOME_REMAINING;

        var notifyRequest = new NotifyRequest(email, notificationType, request.supportedLanguage);
        sqsClient.send(serializationService.writeValueAsString((notifyRequest)));
        LOG.info(
                "Notify request sent with notification type '{}' and publicSubjectId '{}'",
                notificationType,
                request.publicSubjectId);
    }

    private void emitSuccessAuditEvent(
            AuditContext auditContext, PasskeysDeleteRequest request, int currentPasskeyCount) {
        var newPasskeyCount = currentPasskeyCount - 1;
        var passkeyId = request.passkeyId;

        var event = AuthPasskeyDeleteSuccessful.create(auditContext, newPasskeyCount, passkeyId, Clock.systemUTC());

        structuredAuditService.submitAuditEvent(event);
    }

    private void emitFailedAuditEvent(AuditContext auditContext, PasskeysDeleteRequest request) {
        var restrictedPasskeyPair =
                pair(
                        AUDIT_EVENT_RESTRICTED_PASSKEY,
                        Map.of(AUDIT_EVENT_RESTRICTED_PASSKEY_CREDENTIAL_ID, request.passkeyId),
                        true);

        auditService.submitAuditEvent(
                AUTH_PASSKEY_DELETE_FAILED,
                auditContext,
                ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                restrictedPasskeyPair);
    }

    private record PasskeysDeleteRequest(
            String publicSubjectId,
            String token,
            String passkeyId,
            LocaleHelper.SupportedLanguage supportedLanguage) {}
}
