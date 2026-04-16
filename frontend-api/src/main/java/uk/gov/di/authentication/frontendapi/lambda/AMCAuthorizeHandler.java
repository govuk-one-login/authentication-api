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
import uk.gov.di.authentication.frontendapi.services.AccessTokenConstructorService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.MalformedURLException;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AMCAuthorizeHandler extends BaseFrontendHandler<AMCAuthorizeRequest> {
    private final AMCService amcService;
    private final JWKSource<SecurityContext> jwkSource;

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
                        new AccessTokenConstructorService(
                                new JwtService(new KmsConnectionService(configurationService)),
                                configurationService));
        this.dynamoAmcStateService = new DynamoAmcStateService(configurationService);
    }

    @SuppressWarnings("java:S1185")
    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    public AMCAuthorizeHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCService amcService,
            JWKSource<SecurityContext> jwkSource,
            DynamoAmcStateService amcStateService) {
        super(
                AMCAuthorizeRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcService = amcService;
        this.jwkSource = jwkSource;
        this.dynamoAmcStateService = amcStateService;
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
                                publicEncryptionKey ->
                                        amcService.buildAuthorizationResult(
                                                authSessionItem.getInternalCommonSubjectId(),
                                                transportJwtConfig.scope(),
                                                authSessionItem,
                                                userProfile.getPublicSubjectID(),
                                                transportJwtConfig.redirectUri(),
                                                accessTokenConfigsForJourneyType,
                                                publicEncryptionKey,
                                                state));

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

    private Result<AMCFailureReason, RSAPublicKey> getAMCPublicEncryptionKey() {
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
                                                    "No RSA key found on the JWKS endpoint"))
                            .toRSAPublicKey());
        } catch (KeySourceException e) {
            LOG.error("Could not retrieve JWKS", e);
            return Result.failure(AMCFailureReason.JWKS_RETRIEVAL_ERROR);
        } catch (JOSEException e) {
            LOG.error("Could not parse JWK", e);
            return Result.failure(AMCFailureReason.JWKS_RETRIEVAL_ERROR);
        }
    }
}
