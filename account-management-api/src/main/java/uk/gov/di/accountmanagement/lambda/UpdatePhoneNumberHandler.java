package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdatePhoneNumberRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class UpdatePhoneNumberHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private static final Logger LOG = LogManager.getLogger(UpdatePhoneNumberHandler.class);
    private final AuditService auditService;

    public UpdatePhoneNumberHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdatePhoneNumberHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
    }

    public UpdatePhoneNumberHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.codeStorageService =
                new CodeStorageService(new RedisConnectionService(configurationService));
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updatePhoneNumberRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updatePhoneNumberRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOG.info("UpdatePhoneNumberHandler received request");
                            try {
                                UpdatePhoneNumberRequest updatePhoneNumberRequest =
                                        objectMapper.readValue(
                                                input.getBody(), UpdatePhoneNumberRequest.class);
                                boolean isValidOtpCode =
                                        codeStorageService.isValidOtpCode(
                                                updatePhoneNumberRequest.getEmail(),
                                                updatePhoneNumberRequest.getOtp(),
                                                NotificationType.VERIFY_PHONE_NUMBER);
                                if (!isValidOtpCode) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1020);
                                }
                                UserProfile userProfile =
                                        dynamoService.getUserProfileByEmail(
                                                updatePhoneNumberRequest.getEmail());
                                Map<String, Object> authorizerParams =
                                        input.getRequestContext().getAuthorizer();
                                RequestBodyHelper.validatePrincipal(
                                        new Subject(userProfile.getPublicSubjectID()),
                                        authorizerParams);
                                dynamoService.updatePhoneNumber(
                                        updatePhoneNumberRequest.getEmail(),
                                        updatePhoneNumberRequest.getPhoneNumber());
                                LOG.info(
                                        "Phone Number has successfully been updated. Adding message to SQS queue");
                                NotifyRequest notifyRequest =
                                        new NotifyRequest(
                                                updatePhoneNumberRequest.getEmail(),
                                                NotificationType.PHONE_NUMBER_UPDATED);
                                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent.UPDATE_PHONE_NUMBER,
                                        context.getAwsRequestId(),
                                        sessionId,
                                        AuditService.UNKNOWN,
                                        userProfile.getSubjectID(),
                                        userProfile.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        updatePhoneNumberRequest.getPhoneNumber(),
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                LOG.info(
                                        "Message successfully added to queue. Generating successful gateway response");
                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonException | IllegalArgumentException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
