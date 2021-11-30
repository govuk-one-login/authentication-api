package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class AuthenticateHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger(AuthenticateHandler.class);

    private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper = new ObjectMapper();
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
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            String sessionId =
                                    RequestHeaderHelper.getHeaderValueOrElse(
                                            input.getHeaders(), SESSION_ID_HEADER, "");
                            attachSessionIdToLogs(sessionId);
                            LOGGER.info("Request received to the AuthenticateHandler");

                            try {
                                AuthenticateRequest loginRequest =
                                        objectMapper.readValue(
                                                input.getBody(), AuthenticateRequest.class);
                                boolean userHasAccount =
                                        authenticationService.userExists(loginRequest.getEmail());
                                if (!userHasAccount) {
                                    LOGGER.error("The user does not have an account");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1010);
                                }
                                boolean hasValidCredentials =
                                        authenticationService.login(
                                                loginRequest.getEmail(),
                                                loginRequest.getPassword());
                                if (!hasValidCredentials) {
                                    LOGGER.info("Invalid login credentials entered");
                                    return generateApiGatewayProxyErrorResponse(
                                            401, ErrorResponse.ERROR_1008);
                                }
                                LOGGER.info(
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
                            } catch (JsonProcessingException e) {
                                LOGGER.error("Request is missing parameters.");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            }
                        });
    }
}
