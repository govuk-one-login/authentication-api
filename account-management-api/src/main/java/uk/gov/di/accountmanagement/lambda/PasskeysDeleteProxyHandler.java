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
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.http.HttpResponse;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;

public class PasskeysDeleteProxyHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteProxyHandler.class);
    private final ConfigurationService configurationService;
    private final AccountDataApiService accountDataApiService;
    private final SerializationService serializationService = SerializationService.getInstance();
    private final AwsSqsClient sqsClient;
    private final DynamoService dynamoService;

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
    }

    public PasskeysDeleteProxyHandler(
            ConfigurationService configurationService,
            AccountDataApiService accountDataApiService,
            AwsSqsClient sqsClient,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.accountDataApiService = accountDataApiService;
        this.sqsClient = sqsClient;
        this.dynamoService = dynamoService;
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

        var userEmailResult = getUserEmailFromPublicSubjectId(request.publicSubjectId);
        if (userEmailResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
        var userEmail = userEmailResult.getSuccess();

        var currentPasskeyCountResult = getPasskeyCount(request);
        if (currentPasskeyCountResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(500, ErrorResponse.INTERNAL_SERVER_ERROR);
        }
        var currentPasskeyCount = currentPasskeyCountResult.getSuccess();

        var deletePasskeyResponseResult = deletePasskey(request);
        if (deletePasskeyResponseResult.isFailure()) {
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
        } else {
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

    private Result<PasskeysDeleteProxyFailureReason, String> getUserEmailFromPublicSubjectId(String publicSubjectId) {
        var userProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);

        if (userProfile.isEmpty()) {
            LOG.warn("No user profile found for public subject ID{}", publicSubjectId);
            return Result.failure(PasskeysDeleteProxyFailureReason.FAILED_TO_FIND_USER_PROFILE);
        }

        return Result.success(userProfile.get().getEmail());
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

    private void sendEmailNotification(PasskeysDeleteRequest request, String email, int passkeyCount) {
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

    private record PasskeysDeleteRequest(
            String publicSubjectId,
            String token,
            String passkeyId,
            LocaleHelper.SupportedLanguage supportedLanguage) {}
}
