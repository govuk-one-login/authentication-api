package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.TokenResponseError;
import uk.gov.di.authentication.frontendapi.errormapper.AMCFailureHttpMapper;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.frontendapi.services.AccessTokenConstructorService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_STATE_MISMATCH;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AMCCallbackHandler extends BaseFrontendHandler<AMCCallbackRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final AMCService amcService;
    private final DynamoAmcStateService dynamoAmcStateService;

    private static final Logger LOG = LogManager.getLogger(AMCCallbackHandler.class);

    public AMCCallbackHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCCallbackHandler(ConfigurationService configurationService) {
        super(AMCCallbackRequest.class, configurationService, true);
        this.amcService =
                new AMCService(
                        configurationService,
                        new NowHelper.NowClock(Clock.systemUTC()),
                        new JwtService(new KmsConnectionService(configurationService)),
                        new AccessTokenConstructorService(configurationService));
        this.dynamoAmcStateService = new DynamoAmcStateService(configurationService);
    }

    public AMCCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCService amcService,
            DynamoAmcStateService dynamoAmcStateService) {
        super(
                AMCCallbackRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcService = amcService;
        this.dynamoAmcStateService = dynamoAmcStateService;
    }

    @SuppressWarnings("java:S1185")
    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AMCCallbackRequest request,
            UserContext userContext) {

        LOG.info("Request received to AMCCallbackHandler");

        var verifyStateResult = verifyState(request.state(), userContext);
        if (verifyStateResult.isFailure()) {
            return verifyStateResult.getFailure();
        }

        LOG.info("State matches journey id, deleting state from dynamo");
        dynamoAmcStateService.delete(request.state());

        LOG.info("Building token request");

        var requestResult = amcService.buildTokenRequest(request.code(), request.usedRedirectUrl());

        if (requestResult.isFailure()) {
            var failure = requestResult.getFailure();
            LOG.warn("Failure building token request {}", failure.getValue());
            return AMCFailureHttpMapper.toApiGatewayProxyErrorResponse(failure);
        }

        var persistentSessionId =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());

        var additionalAmcHeaders = new HashMap<String, String>();
        additionalAmcHeaders.put("di-persistent-session-id", persistentSessionId);
        additionalAmcHeaders.put("session-id", userContext.getAuthSession().getSessionId());
        additionalAmcHeaders.put("client-session-id", userContext.getClientSessionId());
        additionalAmcHeaders.put("x-forwarded-for", IpAddressHelper.extractIpAddress(input));
        additionalAmcHeaders.put("user-language", userContext.getUserLanguage().getLanguage());

        if (Objects.nonNull(userContext.getTxmaAuditEncoded())) {
            additionalAmcHeaders.put("txma-audit-encoded", userContext.getTxmaAuditEncoded());
        } else {
            LOG.warn("No txma audit header included");
        }

        var tokenResponse = sendTokenRequest(requestResult.getSuccess(), additionalAmcHeaders);

        if (tokenResponse.isFailure()) {
            return AMCFailureHttpMapper.toApiGatewayProxyErrorResponse(tokenResponse.getFailure());
        }

        LOG.info("AMC token response received");

        var userInfoRequest =
                new UserInfoRequest(
                        configurationService.getAMCJourneyOutcomeURI(),
                        tokenResponse
                                .getSuccess()
                                .toSuccessResponse()
                                .getTokens()
                                .getBearerAccessToken());

        return amcService
                .requestJourneyOutcome(userInfoRequest, additionalAmcHeaders)
                .fold(
                        error -> {
                            LOG.warn("Error requesting journey outcome: {}", error.getValue());
                            return AMCFailureHttpMapper.toApiGatewayProxyErrorResponse(error);
                        },
                        response -> {
                            LOG.info("Journey outcome received successfully");
                            return generateApiGatewayProxyResponse(200, response.getContent());
                        });
    }

    private Result<TokenResponseError, TokenResponse> sendTokenRequest(
            TokenRequest tokenRequest, Map<String, String> amcHeaders) {
        try {
            var request = tokenRequest.toHTTPRequest();
            amcHeaders.forEach(request::setHeader);
            var response = request.send();
            if (!response.indicatesSuccess()) {
                LOG.warn(
                        "Error {} when attempting to call AMC token endpoint: {}",
                        response.getStatusCode(),
                        response.getContent());
                return Result.failure(TokenResponseError.ERROR_RESPONSE_FROM_TOKEN_REQUEST);
            }
            return Result.success(TokenResponse.parse(response));
        } catch (IOException e) {
            LOG.warn("IO Exception when attempting to get token response: {}", e.getMessage());
            return Result.failure(TokenResponseError.IO_EXCEPTION);
        } catch (ParseException e) {
            LOG.warn("Parse exception when attempting to parse token response: {}", e.getMessage());
            return Result.failure(TokenResponseError.PARSE_EXCEPTION);
        }
    }

    private Result<APIGatewayProxyResponseEvent, Void> verifyState(
            String requestState, UserContext userContext) {
        var amcStateMaybe = dynamoAmcStateService.getNonExpiredState(requestState);
        if (amcStateMaybe.isEmpty()) {
            LOG.error("Cannot match received state to a recorded state");
            return Result.failure(generateApiGatewayProxyErrorResponse(400, AMC_STATE_MISMATCH));
        }

        var amcState = amcStateMaybe.get();
        if (!amcState.getClientSessionId().equals(userContext.getClientSessionId())) {
            LOG.error("Received state belongs to a different session");
            return Result.failure(generateApiGatewayProxyErrorResponse(400, AMC_STATE_MISMATCH));
        }
        return Result.success(null);
    }
}
