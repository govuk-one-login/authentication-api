package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidatorFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.orchestration.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(TokenHandler.class);

    private final TokenService tokenService;
    private final DynamoService dynamoService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final RedisConnectionService redisConnectionService;
    private final TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory;
    private final Json objectMapper = SerializationService.getInstance();

    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";

    public TokenHandler(
            TokenService tokenService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            AuthorisationCodeService authorisationCodeService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            RedisConnectionService redisConnectionService,
            TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory) {
        this.tokenService = tokenService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.redisConnectionService = redisConnectionService;
        this.tokenClientAuthValidatorFactory = tokenClientAuthValidatorFactory;
    }

    public TokenHandler(ConfigurationService configurationService) {
        var kms = new KmsConnectionService(configurationService);

        this.configurationService = configurationService;
        this.redisConnectionService = new RedisConnectionService(configurationService);
        this.tokenService =
                new TokenService(configurationService, this.redisConnectionService, kms);
        this.dynamoService = new DynamoService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService, redisConnectionService, objectMapper);
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(configurationService, kms), configurationService);
        this.tokenClientAuthValidatorFactory =
                new TokenClientAuthValidatorFactory(
                        configurationService, new DynamoClientService(configurationService));
    }

    public TokenHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> tokenRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent tokenRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        LOG.info("Token request received");
        Optional<ErrorObject> invalidRequestParamError =
                tokenService.validateTokenRequestParams(input.getBody());
        if (invalidRequestParamError.isPresent()) {
            LOG.warn(
                    "Invalid Token Request. ErrorCode: {}. ErrorDescription: {}",
                    invalidRequestParamError.get().getCode(),
                    invalidRequestParamError.get().getDescription());
            return generateApiGatewayProxyResponse(
                    400, invalidRequestParamError.get().toJSONObject().toJSONString());
        }

        Map<String, String> requestBody = parseRequestBody(input.getBody());
        addAnnotation("grant_type", requestBody.get("grant_type"));
        ClientRegistry clientRegistry;
        AuthCodeExchangeData authCodeExchangeData;
        JWSAlgorithm signingAlgorithm;
        try {
            var tokenAuthenticationValidator =
                    tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(
                            input.getBody());
            if (tokenAuthenticationValidator.isEmpty()) {
                LOG.warn("Unsupported token authentication method used");
                return generateApiGatewayProxyResponse(
                        400,
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid token authentication method used")
                                .toJSONObject()
                                .toJSONString());
            }
            clientRegistry =
                    tokenAuthenticationValidator
                            .get()
                            .validateTokenAuthAndReturnClientRegistryIfValid(
                                    input.getBody(), input.getHeaders());
            signingAlgorithm =
                    configurationService.isRsaSigningAvailable()
                                    && "RSA256".equals(clientRegistry.getIdTokenSigningAlgorithm())
                            ? JWSAlgorithm.RS256
                            : JWSAlgorithm.ES256;
            if (requestBody.get("grant_type").equals(GrantType.REFRESH_TOKEN.getValue())) {
                LOG.info("Processing refresh token request");
                return segmentedFunctionCall(
                        "processRefreshTokenRequest",
                        () ->
                                processRefreshTokenRequest(
                                        clientRegistry.getScopes(),
                                        new RefreshToken(requestBody.get("refresh_token")),
                                        clientRegistry.getClientID(),
                                        signingAlgorithm));
            }
            authCodeExchangeData =
                    segmentedFunctionCall(
                            "authorisationCodeService",
                            () ->
                                    authorisationCodeService
                                            .getExchangeDataForCode(requestBody.get("code"))
                                            .orElseThrow());
            updateAttachedLogFieldToLogs(
                    CLIENT_SESSION_ID, authCodeExchangeData.getClientSessionId());
            updateAttachedLogFieldToLogs(
                    GOVUK_SIGNIN_JOURNEY_ID, authCodeExchangeData.getClientSessionId());
        } catch (TokenAuthInvalidException e) {
            LOG.warn("Unable to validate token auth method", e);
            return generateApiGatewayProxyResponse(
                    400, e.getErrorObject().toJSONObject().toJSONString());
        } catch (NoSuchElementException e) {
            LOG.warn("Could not retrieve clientRegistry session ID from code", e);
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }

        ClientSession clientSession = authCodeExchangeData.getClientSession();
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        } catch (ParseException e) {
            LOG.warn("Could not parse authentication request from clientRegistry session", e);
            throw new RuntimeException(
                    format(
                            "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                            clientSession.getAuthRequestParams(), e));
        }

        var authRequestRedirectURI = authRequest.getRedirectionURI().toString();
        if (!authRequestRedirectURI.equals(requestBody.get("redirect_uri"))) {
            LOG.warn(
                    "Redirect URI for auth request ({}) does not match redirect URI for request body ({})",
                    authRequestRedirectURI,
                    requestBody.get("redirect_uri"));
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }

        Map<String, Object> additionalTokenClaims = new HashMap<>();
        if (authRequest.getNonce() != null) {
            additionalTokenClaims.put("nonce", authRequest.getNonce());
        }
        String vot = clientSession.getEffectiveVectorOfTrust().retrieveVectorOfTrustForToken();

        OIDCClaimsRequest claimsRequest = null;
        if (Objects.nonNull(clientSession.getEffectiveVectorOfTrust().getLevelOfConfidence())
                && Objects.nonNull(authRequest.getOIDCClaims())) {
            claimsRequest = authRequest.getOIDCClaims();
        }
        var isConsentRequired =
                clientRegistry.isConsentRequired()
                        && !clientSession.getEffectiveVectorOfTrust().containsLevelOfConfidence();
        final OIDCClaimsRequest finalClaimsRequest = claimsRequest;
        OIDCTokenResponse tokenResponse;
        if (isDocCheckingAppUserWithSubjectId(clientSession)) {
            tokenResponse =
                    segmentedFunctionCall(
                            "generateTokenResponse",
                            () ->
                                    tokenService.generateTokenResponse(
                                            clientRegistry.getClientID(),
                                            clientSession.getDocAppSubjectId(),
                                            authRequest.getScope(),
                                            additionalTokenClaims,
                                            clientSession.getDocAppSubjectId(),
                                            clientSession.getDocAppSubjectId(),
                                            null,
                                            false,
                                            finalClaimsRequest,
                                            true,
                                            signingAlgorithm,
                                            authCodeExchangeData.getClientSessionId(),
                                            vot));
        } else {
            UserProfile userProfile =
                    dynamoService.getUserProfileByEmail(authCodeExchangeData.getEmail());
            Subject rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            clientRegistry,
                            dynamoService,
                            configurationService.getInternalSectorUri());
            Subject internalPairwiseSubject =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorUri(),
                            dynamoService);
            tokenResponse =
                    segmentedFunctionCall(
                            "generateTokenResponse",
                            () ->
                                    tokenService.generateTokenResponse(
                                            clientRegistry.getClientID(),
                                            new Subject(userProfile.getSubjectID()),
                                            authRequest.getScope(),
                                            additionalTokenClaims,
                                            rpPairwiseSubject,
                                            internalPairwiseSubject,
                                            userProfile.getClientConsent(),
                                            isConsentRequired,
                                            finalClaimsRequest,
                                            false,
                                            signingAlgorithm,
                                            authCodeExchangeData.getClientSessionId(),
                                            vot));
        }

        clientSessionService.saveClientSession(
                authCodeExchangeData.getClientSessionId(),
                clientSession.setIdTokenHint(
                        tokenResponse.getOIDCTokens().getIDToken().serialize()));
        LOG.info("Successfully generated tokens");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }

    private APIGatewayProxyResponseEvent processRefreshTokenRequest(
            List<String> clientScopes,
            RefreshToken currentRefreshToken,
            String clientId,
            JWSAlgorithm signingAlgorithm) {
        boolean refreshTokenSignatureValid =
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(currentRefreshToken);
        if (!refreshTokenSignatureValid) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        Subject rpPairwiseSubject;
        List<String> scopes;
        String jti;
        try {
            SignedJWT signedJwt = SignedJWT.parse(currentRefreshToken.getValue());
            rpPairwiseSubject = new Subject(signedJwt.getJWTClaimsSet().getSubject());
            scopes = (List<String>) signedJwt.getJWTClaimsSet().getClaim("scope");
            jti = signedJwt.getJWTClaimsSet().getJWTID();
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse RefreshToken");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        boolean areScopesValid =
                tokenValidationService.validateRefreshTokenScopes(clientScopes, scopes);
        if (!areScopesValid) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_SCOPE.toJSONObject().toJSONString());
        }

        String redisKey = REFRESH_TOKEN_PREFIX + jti;
        Optional<String> refreshToken =
                Optional.ofNullable(redisConnectionService.popValue(redisKey));
        RefreshTokenStore tokenStore;
        try {
            tokenStore = objectMapper.readValue(refreshToken.get(), RefreshTokenStore.class);
        } catch (JsonException | NoSuchElementException | IllegalArgumentException e) {
            LOG.warn("Refresh token not found with given key");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }
        if (!tokenStore.getRefreshToken().equals(currentRefreshToken.getValue())) {
            LOG.warn("Refresh token store does not contain Refresh token in request");
            return generateApiGatewayProxyResponse(
                    400,
                    new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                            .toJSONObject()
                            .toJSONString());
        }

        OIDCTokenResponse tokenResponse =
                tokenService.generateRefreshTokenResponse(
                        clientId,
                        new Subject(tokenStore.getInternalSubjectId()),
                        scopes,
                        rpPairwiseSubject,
                        new Subject(tokenStore.getInternalPairwiseSubjectId()),
                        signingAlgorithm);
        LOG.info("Generating successful RefreshToken response");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }
}
