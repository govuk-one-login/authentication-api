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
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_DELETE_COMPLETED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

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
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1063);
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var mfaIdentifier = input.getPathParameters().get("mfaIdentifier");

        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        if (mfaIdentifier.isEmpty()) {
            LOG.error("Request does not include mfa identifier");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        var maybeUserProfile =
                dynamoService.getOptionalUserProfileFromPublicSubject(publicSubjectId);
        if (maybeUserProfile.isEmpty()) {
            LOG.error("Unknown public subject ID");
            return generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056);
        }
        UserProfile userProfile = maybeUserProfile.get();

        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
        if (PrincipalValidationHelper.principalIsInvalid(
                userProfile,
                configurationService.getInternalSectorUri(),
                dynamoService,
                authorizerParams)) {
            return generateApiGatewayProxyErrorResponse(401, ErrorResponse.ERROR_1079);
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
                        409, ErrorResponse.ERROR_1066);
                case CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER -> generateApiGatewayProxyErrorResponse(
                        400, ErrorResponse.ERROR_1067);
                case MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST -> generateApiGatewayProxyErrorResponse(
                        404, ErrorResponse.ERROR_1065);
            };
        }

        LOG.info("MFA method deleted {}", mfaIdentifier);

        Result<ErrorResponse, AuditContext> auditContextResult =
                buildAuditContext(input, userProfile, deleteResult.getSuccess());

        if (auditContextResult.isFailure()) {
            return generateApiGatewayProxyErrorResponse(401, auditContextResult.getFailure());
        }

        auditService.submitAuditEvent(
                AUTH_MFA_METHOD_DELETE_COMPLETED, auditContextResult.getSuccess());

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
        attachSessionIdToLogs(sessionId);
    }

    private Result<ErrorResponse, AuditContext> buildAuditContext(
            APIGatewayProxyRequestEvent input, UserProfile userProfile, MFAMethod mfaMethod) {
        try {

            var phoneNumber =
                    mfaMethod.getMfaMethodType().equals(MFAMethodType.SMS.name())
                            ? mfaMethod.getDestination()
                            : AuditService.UNKNOWN;

            var metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(
                                AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                JourneyType.ACCOUNT_MANAGEMENT.getValue()),
                        pair(AUDIT_EVENT_EXTENSIONS_MFA_TYPE, mfaMethod.getMfaMethodType())
                    };

            var context =
                    new AuditContext(
                            input.getRequestContext()
                                    .getAuthorizer()
                                    .getOrDefault(ATTRIBUTE_CLIENT_ID, AuditService.UNKNOWN)
                                    .toString(),
                            ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                            RequestHeaderHelper.getHeaderValueOrElse(
                                    input.getHeaders(), SESSION_ID_HEADER, ""),
                            ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                            userProfile,
                                            configurationService.getInternalSectorUri(),
                                            dynamoService)
                                    .getValue(),
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            phoneNumber,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            AuditHelper.getTxmaAuditEncoded(input.getHeaders()),
                            List.of(metadataPairs));

            return Result.success(context);
        } catch (Exception e) {
            LOG.error("Error building audit context", e);
            return Result.failure(ErrorResponse.ERROR_1071);
        }
    }
}
