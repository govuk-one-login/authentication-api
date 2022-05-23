package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class AuthenticateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthenticateHandler.class);

    private final AuthenticationService authenticationService;
    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService;

    public AuthenticateHandler(
            AuthenticationService authenticationService, AuditService auditService) {
        this.authenticationService = authenticationService;
        this.auditService = auditService;
    }

    public AuthenticateHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthenticateHandler(ConfigurationService configurationService) {
        this.authenticationService = new DynamoService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> authenticateRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authenticateRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOG.info("Request received to the AuthenticateHandler");

                            try {
                                AuthenticateRequest loginRequest =
                                        objectMapper.readValue(
                                                input.getBody(), AuthenticateRequest.class);
                                boolean userHasAccount =
                                        authenticationService.userExists(loginRequest.getEmail());
                                if (!userHasAccount) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1010);
                                }
                                boolean hasValidCredentials =
                                        authenticationService.login(
                                                loginRequest.getEmail(),
                                                loginRequest.getPassword());
                                if (!hasValidCredentials) {
                                    return generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.ERROR_1008);
                                }
                                LOG.info(
                                        "User has successfully Logged in. Generating successful AuthenticateResponse");

                                auditService.submitAuditEvent(
                                        AccountManagementAuditableEvent
                                                .ACCOUNT_MANAGEMENT_AUTHENTICATE,
                                        context.getAwsRequestId(),
                                        sessionId,
                                        AuditService.UNKNOWN,
                                        AuditService.UNKNOWN,
                                        loginRequest.getEmail(),
                                        IpAddressHelper.extractIpAddress(input),
                                        AuditService.UNKNOWN,
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                return generateEmptySuccessApiGatewayResponse();
                            } catch (JsonException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
