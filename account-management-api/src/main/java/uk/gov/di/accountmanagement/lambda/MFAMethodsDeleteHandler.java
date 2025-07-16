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
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.Map;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_DELETE_COMPLETED;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;

public class MFAMethodsDeleteHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(MFAMethodsDeleteHandler.class);
    private final ConfigurationService configurationService;
    private final MFAMethodsService mfaMethodsService;
    private final DynamoService dynamoService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;

    public MFAMethodsDeleteHandler() {
        this(ConfigurationService.getInstance());
    }

    public MFAMethodsDeleteHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.sqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getEmailQueueUri(),
                        configurationService.getSqsEndpointUri());
        this.auditService = new AuditService(configurationService);
    }

    public MFAMethodsDeleteHandler(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            DynamoService dynamoService,
            AwsSqsClient sqsClient,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.dynamoService = dynamoService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> deleteMFAMethodHandler(input, context));
    }

    public APIGatewayProxyResponseEvent deleteMFAMethodHandler(
            APIGatewayProxyRequestEvent input, Context context) throws Json.JsonException {

        addSessionIdToLogs(input);

        if (!configurationService.isMfaMethodManagementApiEnabled()) {
            LOG.error(
                    "Request to delete MFA method in {} environment but feature is switched off.",
                    configurationService.getEnvironment());
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.MM_API_NOT_AVAILABLE);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var mfaIdentifier = input.getPathParameters().get("mfaIdentifier");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }

        if (mfaIdentifier.isEmpty()) {
            LOG.error("Request does not include mfa identifier");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.REQUEST_MISSING_PARAMS);
        }

        var maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);
        if (maybeUserProfile.isEmpty()) {
            LOG.error("Unknown public subject ID");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.USER_NOT_FOUND);
        }
        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                dynamoService,
                authorizerParams)) {
            return generateApiGatewayProxyErrorResponse(401, ErrorResponse.INVALID_PRINCIPAL);
        }

        var deleteResult = mfaMethodsService.deleteMfaMethod(mfaIdentifier, userProfile);

        if (deleteResult.isFailure()) {
            var failureReason = deleteResult.getFailure();
            LOG.warn(
                    "Attempted to delete mfa with identifier {} but failed for reason {}",
                    mfaIdentifier,
                    failureReason.name());
            return switch (failureReason) {
                case CANNOT_DELETE_DEFAULT_METHOD -> generateApiGatewayProxyErrorResponse(
                        409, ErrorResponse.CANNOT_DELETE_DEFAULT_MFA);
                case CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER -> generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.CANNOT_DELETE_MFA_FOR_UNMIGRATED_USER);
                case MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST -> generateApiGatewayProxyErrorResponse(
                        404, ErrorResponse.MFA_METHOD_NOT_FOUND);
            };
        }

        LOG.info("MFA method deleted {}", mfaIdentifier);

        Result<ErrorResponse, AuditContext> auditContextResult =
                buildAuditContext(input, userProfile, deleteResult.getSuccess());

        if (auditContextResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(401, auditContextResult.getFailure());
        }

        auditService.submitAuditEvent(
                AUTH_MFA_METHOD_DELETE_COMPLETED,
                auditContextResult.getSuccess(),
                AUDIT_EVENT_COMPONENT_ID_HOME);

        LOG.info("Audit event emitted.");

        LocaleHelper.SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        userProfile.getEmail(),
                        NotificationType.BACKUP_METHOD_REMOVED,
                        userLanguage);
        sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));

        LOG.info("Notify request sent.");

        return generateEmptySuccessApiGatewayResponse();
    }

    private void addSessionIdToLogs(APIGatewayProxyRequestEvent input) {
        Map<String, String> headers = input.getHeaders();
        String sessionId = RequestHeaderHelper.getHeaderValueOrElse(headers, SESSION_ID_HEADER, "");
        uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs(sessionId);
    }

    private Result<ErrorResponse, AuditContext> buildAuditContext(
            APIGatewayProxyRequestEvent input, UserProfile userProfile, MFAMethod mfaMethod) {
        return AuditHelper.buildAuditContextForMfaMethod(
                input, userProfile, mfaMethod, configurationService, dynamoService, LOG);
    }
}
