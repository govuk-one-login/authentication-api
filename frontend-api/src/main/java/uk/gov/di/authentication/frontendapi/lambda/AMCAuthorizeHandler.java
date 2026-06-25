package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizationUrlAndCookie;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizeRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizeResponse;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenConfig;
import uk.gov.di.authentication.frontendapi.entity.amc.TransportJWTConfig;
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
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.services.JwtService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.MalformedURLException;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_AMC_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_AMC_SCOPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.AMC_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.AMC_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AMCAuthorizeHandler extends BaseFrontendHandler<AMCAuthorizeRequest> {
    private final AMCService amcService;
    private final JWKSource<SecurityContext> jwkSource;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    private static final Logger LOG = LogManager.getLogger(AMCAuthorizeHandler.class);
    private final DynamoAmcStateService dynamoAmcStateService;

    public AMCAuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCAuthorizeHandler(ConfigurationService configurationService) {
        super(AMCAuthorizeRequest.class, configurationService);
        try {
            this.jwkSource =
                    JWKSourceBuilder.create(configurationService.getAmcJwksUrl())
                            .retrying(true)
                            .refreshAheadCache(false)
                            .cache(true)
                            .rateLimited(false)
                            .build();
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Invalid AMC JWKS URL: " + e.getMessage(), e);
        }
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

    public AMCAuthorizeHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCService amcService,
            JWKSource<SecurityContext> jwkSource,
            DynamoAmcStateService amcStateService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                AMCAuthorizeRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcService = amcService;
        this.jwkSource = jwkSource;
        this.dynamoAmcStateService = amcStateService;
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
            AMCAuthorizeRequest request,
            UserContext userContext) {

        AuthSessionItem authSessionItem = userContext.getAuthSession();
        var userProfile =
                authenticationService
                        .getUserProfileByEmailMaybe(authSessionItem.getEmailAddress())
                        .orElse(null);

        if (userProfile == null) {
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.EMAIL_HAS_NO_USER_PROFILE);
        }

        List<AccessTokenConfig> accessTokenConfigsForJourneyType =
                request.amcJourneyType().getAccessTokenConfigs(configurationService);
        TransportJWTConfig transportJwtConfig =
                request.amcJourneyType().getTransportJwtConfig(configurationService);
        var state = new State();
        dynamoAmcStateService.store(state.getValue(), userContext.getClientSessionId());

        Result<AMCFailureReason, AMCAuthorizationUrlAndCookie> result =
                getAMCPublicEncryptionKey()
                        .flatMap(
                                rsaKey -> {
                                    try {
                                        return amcService.buildAuthorizationResult(
                                                authSessionItem.getInternalCommonSubjectId(),
                                                transportJwtConfig.scope(),
                                                authSessionItem,
                                                userProfile.getPublicSubjectID(),
                                                transportJwtConfig.redirectUri(),
                                                accessTokenConfigsForJourneyType,
                                                rsaKey.toRSAPublicKey(),
                                                rsaKey.getKeyID(),
                                                state);
                                    } catch (JOSEException e) {
                                        LOG.error("Could not parse JWK", e);
                                        return Result.failure(
                                                AMCFailureReason.JWKS_RETRIEVAL_ERROR);
                                    }
                                });

        reportAuthorizationRequested(userContext, input, request);

        return result.fold(
                AMCFailureHttpMapper::toApiGatewayProxyErrorResponse,
                success -> {
                    try {
                        return generateApiGatewayProxyResponse(
                                200, new AMCAuthorizeResponse(success.url(), success.amcCookie()));
                    } catch (Json.JsonException e) {
                        return generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.SERIALIZATION_ERROR);
                    }
                });
    }

    private void reportAuthorizationRequested(
            UserContext userContext,
            APIGatewayProxyRequestEvent input,
            AMCAuthorizeRequest request) {
        emitAuthorizationRequestedAuditEvent(userContext, input, request);
        emitAmcAuthorisationRequestedMetric(request);
    }

    private void emitAuthorizationRequestedAuditEvent(
            UserContext userContext,
            APIGatewayProxyRequestEvent input,
            AMCAuthorizeRequest request) {
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        userContext.getAuthSession().getEmailAddress(),
                        IpAddressHelper.extractIpAddress(input),
                        AuditService
                                .UNKNOWN, // the schema does not include phone number for this event
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var amcScopeForAuditEvent =
                switch (request.amcJourneyType()) {
                    case PASSKEY_CREATE -> "passkey-create";
                    case SFAD -> "sfad"; // note we'll probably want to review this when we get to
                        // implementing sfad fully
                };

        var journeyTypePair = pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, JourneyType.SIGN_IN);
        var amcScopePair = pair(AUDIT_EVENT_EXTENSIONS_AMC_SCOPE, amcScopeForAuditEvent);
        auditService.submitAuditEvent(
                AUTH_AMC_AUTHORISATION_REQUESTED, auditContext, journeyTypePair, amcScopePair);
    }

    private void emitAmcAuthorisationRequestedMetric(AMCAuthorizeRequest request) {
        var dimensions =
                Map.ofEntries(
                        Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                        Map.entry(AMC_JOURNEY_TYPE.getValue(), request.amcJourneyType().name()));
        cloudwatchMetricsService.incrementCounter(AMC_AUTHORISATION_REQUESTED, dimensions);
    }

    private Result<AMCFailureReason, RSAKey> getAMCPublicEncryptionKey() {
        LOG.info("Retrieving RSA encryption JWK from AMC JWKS endpoint for auth -> AMC encryption");
        try {
            return Result.success(
                    this.jwkSource
                            .get(
                                    new JWKSelector(
                                            new JWKMatcher.Builder().keyType(KeyType.RSA).build()),
                                    null)
                            .stream()
                            .map(RSAKey.class::cast)
                            .findFirst()
                            .orElseThrow(
                                    () ->
                                            new KeySourceException(
                                                    "No RSA key found on the JWKS endpoint")));
        } catch (KeySourceException e) {
            LOG.error("Could not retrieve JWKS", e);
            return Result.failure(AMCFailureReason.JWKS_RETRIEVAL_ERROR);
        }
    }
}
