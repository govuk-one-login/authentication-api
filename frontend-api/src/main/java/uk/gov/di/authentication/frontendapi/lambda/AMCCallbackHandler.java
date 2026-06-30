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
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeResponse;
import uk.gov.di.authentication.frontendapi.entity.amc.TokenResponseError;
import uk.gov.di.authentication.frontendapi.errormapper.AMCFailureHttpMapper;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.services.JwtService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_ERRORS;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_FAILED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTION_OVERALL_OUTCOME;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_AMC_SCOPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.AMC_AUTHORISATION_OVERALL_SUCCESS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.AMC_SCOPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AMC_AUTHORISATION_RECEIVED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AMC_FAILURE_GETTING_AUTHORISATION;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_STATE_MISMATCH;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AMCCallbackHandler extends BaseFrontendHandler<AMCCallbackRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private final AMCService amcService;
    private final DynamoAmcStateService dynamoAmcStateService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

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
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
    }

    public AMCCallbackHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCService amcService,
            DynamoAmcStateService dynamoAmcStateService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                AMCCallbackRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcService = amcService;
        this.dynamoAmcStateService = dynamoAmcStateService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
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
            reportFailureGettingAuthorisation("StateVerificationFailure");
            return verifyStateResult.getFailure();
        }

        LOG.info("State matches journey id, deleting state from dynamo");
        dynamoAmcStateService.delete(request.state());

        LOG.info("Building token request");

        var requestResult = amcService.buildTokenRequest(request.code(), request.usedRedirectUrl());

        if (requestResult.isFailure()) {
            var failure = requestResult.getFailure();
            LOG.warn("Failure building token request {}", failure.getValue());
            reportFailureGettingAuthorisation("FailureBuildingTokenRequest");
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

        if (!userContext.getTxmaAuditEncoded().isEmpty()) {
            additionalAmcHeaders.put("txma-audit-encoded", userContext.getTxmaAuditEncoded());
        } else {
            LOG.warn("No txma audit header included");
        }

        var tokenResponse = sendTokenRequest(requestResult.getSuccess(), additionalAmcHeaders);

        if (tokenResponse.isFailure()) {
            reportFailureGettingAuthorisation("FailureRetrievingTokenResponse");
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
                            reportFailureGettingAuthorisation("FailureRetrievingJourneyOutcome");
                            return AMCFailureHttpMapper.toApiGatewayProxyErrorResponse(error);
                        },
                        response -> {
                            JourneyOutcomeResponse journeyOutcome;
                            try {
                                journeyOutcome =
                                        SerializationService.getInstance()
                                                .readValue(
                                                        response.getBody(),
                                                        JourneyOutcomeResponse.class);
                            } catch (JsonException e) {
                                LOG.error("Failed to parse journey outcome response", e);
                                reportFailureGettingAuthorisation("FailedToParseJourneyOutcome");
                                return generateApiGatewayProxyErrorResponse(
                                        500, ErrorResponse.AMC_JOURNEY_OUTCOME_UNEXPECTED_ERROR);
                            }

                            reportAuthorisationReceived(journeyOutcome, userContext, input);

                            LOG.info("Journey outcome received successfully");
                            return generateApiGatewayProxyResponse(200, response.getBody());
                        });
    }

    private void reportFailureGettingAuthorisation(String failureReason) {
        var metricDimensions =
                Map.ofEntries(
                        Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                        Map.entry(FAILURE_REASON.getValue(), failureReason));
        cloudwatchMetricsService.incrementCounter(
                AMC_FAILURE_GETTING_AUTHORISATION, metricDimensions);
    }

    private void reportAuthorisationReceived(
            JourneyOutcomeResponse journeyOutcome,
            UserContext userContext,
            APIGatewayProxyRequestEvent input) {
        emitAuthorisationReceivedAuditEvent(journeyOutcome, userContext, input);
        emitAuthorisationReceivedMetric(journeyOutcome);
    }

    private void emitAuthorisationReceivedMetric(JourneyOutcomeResponse journeyOutcomeResponse) {
        var metricDimensions =
                Map.ofEntries(
                        Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                        Map.entry(
                                AMC_AUTHORISATION_OVERALL_SUCCESS.getValue(),
                                String.valueOf(journeyOutcomeResponse.success())),
                        Map.entry(AMC_SCOPE.getValue(), journeyOutcomeResponse.scope()));
        cloudwatchMetricsService.incrementCounter(AMC_AUTHORISATION_RECEIVED, metricDimensions);
    }

    private void emitAuthorisationReceivedAuditEvent(
            JourneyOutcomeResponse journeyOutcome,
            UserContext userContext,
            APIGatewayProxyRequestEvent input) {

        var failedActions = new ArrayList<String>();
        var actionErrors = new ArrayList<String>();
        var allActions = new ArrayList<String>();

        for (var action : Optional.ofNullable(journeyOutcome.actions()).orElse(List.of())) {
            allActions.add(action.action());
            if (!action.success()) {
                failedActions.add(action.action());
                if (action.details() != null && action.details().error() != null) {
                    actionErrors.add(action.details().error().description());
                }
            }
        }

        AuthSessionItem authSessionItem = userContext.getAuthSession();

        var auditContext =
                new AuditContext(
                        authSessionItem.getClientId(),
                        userContext.getClientSessionId(),
                        authSessionItem.getSessionId(),
                        authSessionItem.getInternalCommonSubjectId(),
                        authSessionItem.getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                        userContext.getTxmaAuditEncoded());

        Object journeyType =
                AMCScope.fromValue(journeyOutcome.scope())
                        .<Object>map(
                                scope ->
                                        switch (scope) {
                                            case PASSKEY_CREATE -> JourneyType.SIGN_IN;
                                                // This may not be the right journey type for
                                                // ACCOUNT_DELETE,
                                                // this needs to be clarified as part of the SFAD
                                                // initiative
                                            case ACCOUNT_DELETE -> JourneyType.ACCOUNT_RECOVERY;
                                        })
                        .orElseGet(
                                () -> {
                                    LOG.info(
                                            "Unexpected scope returned in AMC journey outcome response");
                                    return AuditService.UNKNOWN;
                                });

        auditService.submitAuditEvent(
                FrontendAuditableEvent.AUTH_AMC_AUTHORISATION_RECEIVED,
                auditContext,
                pair(
                        AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTION_OVERALL_OUTCOME,
                        journeyOutcome.success()),
                pair(AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS, allActions),
                pair(AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_ERRORS, actionErrors),
                pair(AUDIT_EVENT_EXTENSIONS_ACCOUNT_ACTIONS_FAILED, failedActions),
                pair(AUDIT_EVENT_EXTENSIONS_AMC_SCOPE, journeyOutcome.scope()),
                pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, journeyType));
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
                        response.getBody());
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
