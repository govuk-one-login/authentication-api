package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeRequest;
import uk.gov.di.authentication.frontendapi.entity.AuthCodeResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AuthenticationAuthCodeHandler extends BaseFrontendHandler<AuthCodeRequest> {

    private static final Logger LOG = LogManager.getLogger(AuthenticationAuthCodeHandler.class);

    private final DynamoAuthCodeService dynamoAuthCodeService;

    public AuthenticationAuthCodeHandler(
            DynamoAuthCodeService dynamoAuthCodeService,
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService) {
        super(
                AuthCodeRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.dynamoAuthCodeService = dynamoAuthCodeService;
    }

    public AuthenticationAuthCodeHandler(ConfigurationService configurationService) {
        super(AuthCodeRequest.class, configurationService);
        this.dynamoAuthCodeService = new DynamoAuthCodeService(configurationService);
    }

    public AuthenticationAuthCodeHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        super(AuthCodeRequest.class, configurationService, redis);
        this.dynamoAuthCodeService = new DynamoAuthCodeService(configurationService);
    }

    public AuthenticationAuthCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AuthCodeRequest authCodeRequest,
            UserContext userContext) {
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        try {
            var userProfile = userContext.getUserProfile();
            if (userProfile.isEmpty()) {
                LOG.info(
                        "Error message: Email from session does not have a user profile required to extract Subject ID");
                return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
            }

            var authorisationCode = new AuthorizationCode();
            dynamoAuthCodeService.saveAuthCode(
                    userProfile.get().getSubjectID(),
                    authorisationCode.getValue(),
                    authCodeRequest.claims(),
                    false,
                    authCodeRequest.sectorIdentifier(),
                    authCodeRequest.isNewAccount(),
                    authCodeRequest.passwordResetTime());

            var state = State.parse(authCodeRequest.state());
            var redirectUri = URI.create(authCodeRequest.redirectUri());
            var authorizationResponse =
                    new AuthorizationSuccessResponse(
                            redirectUri, authorisationCode, null, state, null);

            return generateApiGatewayProxyResponse(
                    200, new AuthCodeResponse(authorizationResponse.toURI().toString()));
        } catch (JsonException ex) {
            LOG.warn("Exception generating authcode. Returning 1001: ", ex);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
