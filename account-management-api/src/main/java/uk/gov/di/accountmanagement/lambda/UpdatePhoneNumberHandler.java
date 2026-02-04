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
import uk.gov.di.accountmanagement.entity.UpdatePhoneNumberRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.Map;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class UpdatePhoneNumberHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final CodeStorageService codeStorageService;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(UpdatePhoneNumberHandler.class);
    private final AuditService auditService;

    public UpdatePhoneNumberHandler() {
        this(ConfigurationService.getInstance());
    }

    public UpdatePhoneNumberHandler(
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            CodeStorageService codeStorageService,
            AuditService auditService,
            ConfigurationService configurationService) {
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.codeStorageService = codeStorageService;
        this.auditService = auditService;
        this.configurationService = configurationService;
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
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> updatePhoneNumberRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent updatePhoneNumberRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachTraceId();
        attachSessionIdToLogs(sessionId);
        LOG.info("UpdatePhoneNumberHandler received request");
        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));
        try {
            UpdatePhoneNumberRequest updatePhoneNumberRequest =
                    objectMapper.readValue(input.getBody(), UpdatePhoneNumberRequest.class);
            boolean isValidOtpCode =
                    codeStorageService.isValidOtpCode(
                            updatePhoneNumberRequest.getEmail(),
                            updatePhoneNumberRequest.getOtp(),
                            NotificationType.VERIFY_PHONE_NUMBER);
            if (!isValidOtpCode) {
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.INVALID_OTP);
            }
            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(updatePhoneNumberRequest.getEmail())
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            if (PrincipalValidationHelper.principalIsInvalid(
                    userProfile,
                    configurationService.getInternalSectorUri(),
                    dynamoService,
                    authorizerParams)) {
                throw new InvalidPrincipalException("Invalid Principal in request");
            }
            dynamoService.updatePhoneNumber(
                    updatePhoneNumberRequest.getEmail(), updatePhoneNumberRequest.getPhoneNumber());
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            updatePhoneNumberRequest.getEmail(),
                            NotificationType.PHONE_NUMBER_UPDATED,
                            userLanguage);
            LOG.info(
                    "Phone Number has successfully been updated. Adding message to SQS queue,  reference: {}",
                    notifyRequest.getUniqueNotificationReference());
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

            LOG.info("Calculating internal common subject identifier");
            var internalCommonSubjectIdentifier =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            dynamoService);

            var auditContext =
                    new AuditContext(
                            input.getRequestContext()
                                    .getAuthorizer()
                                    .getOrDefault("clientId", AuditService.UNKNOWN)
                                    .toString(),
                            ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                            sessionId,
                            internalCommonSubjectIdentifier.getValue(),
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            updatePhoneNumberRequest.getPhoneNumber(),
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                            new ArrayList<>());

            auditService.submitAuditEvent(
                    AUTH_UPDATE_PHONE_NUMBER, auditContext, AUDIT_EVENT_COMPONENT_ID_HOME);

            LOG.info("Message successfully added to queue. Generating successful gateway response");
            return generateEmptySuccessApiGatewayResponse();
        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ACCT_DOES_NOT_EXIST);
        } catch (JsonException | IllegalArgumentException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }
    }
}
