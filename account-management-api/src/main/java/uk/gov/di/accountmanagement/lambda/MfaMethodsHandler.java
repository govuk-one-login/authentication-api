package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.MfaMethodsRequest;
import uk.gov.di.accountmanagement.entity.MfaMethodsResponse;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.PrincipalValidationHelper;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.exceptions.UserNotFoundException;
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
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getUserLanguageFromRequestHeaders;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.matchSupportedLanguage;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class MfaMethodsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoService dynamoService;
    private static final Logger LOG = LogManager.getLogger(MfaMethodsHandler.class);
    private final AuditService auditService;
    private final ConfigurationService configurationService;

    public MfaMethodsHandler() {
        this(ConfigurationService.getInstance());
    }

    public MfaMethodsHandler(
            DynamoService dynamoService,
            AuditService auditService,
            ConfigurationService configurationService) {
        this.dynamoService = dynamoService;
        this.auditService = auditService;
        this.configurationService = configurationService;
    }

    public MfaMethodsHandler(ConfigurationService configurationService) {
        this.dynamoService = new DynamoService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.configurationService = configurationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> mfaMethodsRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent mfaMethodsRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        String sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        attachSessionIdToLogs(sessionId);
        LOG.info("MfaMethodsHandler received request");
        SupportedLanguage userLanguage =
                matchSupportedLanguage(
                        getUserLanguageFromRequestHeaders(
                                input.getHeaders(), configurationService));
        try {
            MfaMethodsRequest mfaMethodsRequest =
                    objectMapper.readValue(input.getBody(), MfaMethodsRequest.class);

            var userProfile =
                    dynamoService
                            .getUserProfileByEmailMaybe(mfaMethodsRequest.getEmail())
                            .orElseThrow(
                                    () ->
                                            new UserNotFoundException(
                                                    "User not found with given email"));

            Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();
            if (PrincipalValidationHelper.principleIsInvalid(
                    userProfile,
                    configurationService.getInternalSectorUri(),
                    dynamoService,
                    authorizerParams)) {
                throw new InvalidPrincipalException("Invalid Principal in request");
            }

            UserCredentials userCredentials =
                    dynamoService.getUserCredentialsFromEmail(mfaMethodsRequest.getEmail());

            LOG.info("Calculating internal common subject identifier");
            var internalCommonSubjectIdentifier =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            dynamoService);

            auditService.submitAuditEvent(
                    AccountManagementAuditableEvent.GET_MFA_METHODS,
                    AuditService.UNKNOWN,
                    sessionId,
                    AuditService.UNKNOWN,
                    internalCommonSubjectIdentifier.getValue(),
                    mfaMethodsRequest.getEmail(),
                    IpAddressHelper.extractIpAddress(input),
                    userProfile.getPhoneNumber(),
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

            MfaMethodsResponse mfaMethodsResponse =
                    new MfaMethodsResponse(userCredentials.getMfaMethods());

            LOG.info("Message successfully added to queue. Generating successful gateway response");
            return generateApiGatewayProxyResponse(200, mfaMethodsResponse);

        } catch (UserNotFoundException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1010);
        } catch (JsonException | IllegalArgumentException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
