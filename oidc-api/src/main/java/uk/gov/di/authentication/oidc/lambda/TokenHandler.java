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
import uk.gov.di.orchestration.shared.entity.VtrList;
import uk.gov.di.orchestration.shared.exceptions.InvalidRedirectUriException;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthUnsupportedMethodException;
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
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidator;
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
                "oidc-api::" + getClass().getSimpleName(), () -> tokenRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent tokenRequestHandler(APIGatewayProxyRequestEvent input) {
        ThreadContext.clearMap();
        LOG.info("Token request received");
        Optional<ErrorObject> invalidRequestParamError =
                tokenService.validateTokenRequestParams(input.getBody());
        if (invalidRequestParamError.isPresent()) {
            return invalidRequestResponse(invalidRequestParamError.get());
        }

        Map<String, String> requestBody = parseRequestBody(input.getBody());
        addAnnotation("grant_type", requestBody.get("grant_type"));

        TokenClientAuthValidator tokenAuthenticationValidator;
        try {
            tokenAuthenticationValidator = getTokenAuthenticationMethod(requestBody);
        } catch (TokenAuthUnsupportedMethodException e) {
            LOG.warn("Unsupported token authentication method used");
            return generateApiGatewayProxyResponse(
                    400, e.getErrorObject().toJSONObject().toJSONString());
        }

        ClientRegistry clientRegistry;
        try {
            clientRegistry = getClientRegistry(tokenAuthenticationValidator, input);
        } catch (TokenAuthInvalidException e) {
            LOG.warn("Unable to validate token auth method", e);
            return generateApiGatewayProxyResponse(
                    400, e.getErrorObject().toJSONObject().toJSONString());
        }

        if (refreshTokenRequest(requestBody)) {
            LOG.info("Processing refresh token request");
            return segmentedFunctionCall(
                    "processRefreshTokenRequest",
                    () ->
                            processRefreshTokenRequest(
                                    clientRegistry.getScopes(),
                                    new RefreshToken(requestBody.get("refresh_token")),
                                    clientRegistry.getClientID(),
                                    getSigningAlgorithm(clientRegistry)));
        }

        Optional<AuthCodeExchangeData> authCodeExchangeDataMaybe =
                segmentedFunctionCall(
                        "authorisationCodeService",
                        () ->
                                authorisationCodeService.getExchangeDataForCode(
                                        requestBody.get("code")));
        if (authCodeExchangeDataMaybe.isEmpty()) {
            LOG.warn("Could not retrieve session data from code");
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        AuthCodeExchangeData authCodeExchangeData = authCodeExchangeDataMaybe.get();
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, authCodeExchangeData.getClientSessionId());
        updateAttachedLogFieldToLogs(
                GOVUK_SIGNIN_JOURNEY_ID, authCodeExchangeData.getClientSessionId());

        ClientSession clientSession = authCodeExchangeData.getClientSession();
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
            checkRedirectURI(authRequest, requestBody.get("redirect_uri"));
        } catch (ParseException e) {
            LOG.warn("Could not parse authentication request from clientRegistry session", e);
            throw new RuntimeException(
                    format(
                            "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                            clientSession.getAuthRequestParams(), e));
        } catch (InvalidRedirectUriException e) {
            return generateApiGatewayProxyResponse(
                    400, e.getErrorObject().toJSONObject().toJSONString());
        }

        var tokenResponse =
                getTokenResponse(
                        clientSession,
                        clientRegistry,
                        authRequest,
                        getSigningAlgorithm(clientRegistry),
                        authCodeExchangeData);

        clientSessionService.updateStoredClientSession(
                authCodeExchangeData.getClientSessionId(),
                clientSession.setIdTokenHint(
                        tokenResponse.getOIDCTokens().getIDToken().serialize()));
        LOG.info("Successfully generated tokens");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }

    private static boolean refreshTokenRequest(Map<String, String> requestBody) {
        return requestBody.get("grant_type").equals(GrantType.REFRESH_TOKEN.getValue());
    }

    private static APIGatewayProxyResponseEvent invalidRequestResponse(
            ErrorObject invalidRequestParamError) {
        LOG.warn(
                "Invalid Token Request. ErrorCode: {}. ErrorDescription: {}",
                invalidRequestParamError.getCode(),
                invalidRequestParamError.getDescription());
        return generateApiGatewayProxyResponse(
                400, invalidRequestParamError.toJSONObject().toJSONString());
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
            return generateInvalidGrantCodeApiGatewayProxyResponse();
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
            return generateInvalidGrantCodeApiGatewayProxyResponse();
        }
        if (!tokenStore.getRefreshToken().equals(currentRefreshToken.getValue())) {
            LOG.warn("Refresh token store does not contain Refresh token in request");
            return generateInvalidGrantCodeApiGatewayProxyResponse();
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

    private TokenClientAuthValidator getTokenAuthenticationMethod(Map<String, String> requestBody)
            throws TokenAuthUnsupportedMethodException {
        var tokenAuthenticationValidator =
                tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(requestBody);
        if (tokenAuthenticationValidator.isEmpty()) {
            LOG.warn("Unsupported token authentication method used");
            throw new TokenAuthUnsupportedMethodException(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid token authentication method used"));
        }
        return tokenAuthenticationValidator.get();
    }

    private ClientRegistry getClientRegistry(
            TokenClientAuthValidator tokenAuthenticationValidator,
            APIGatewayProxyRequestEvent request)
            throws TokenAuthInvalidException {
        return tokenAuthenticationValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                request.getBody(), request.getHeaders());
    }

    private JWSAlgorithm getSigningAlgorithm(ClientRegistry clientRegistry) {
        return configurationService.isRsaSigningAvailable()
                        && clientRegistry
                                .getIdTokenSigningAlgorithm()
                                .equals(JWSAlgorithm.RS256.getName())
                ? JWSAlgorithm.RS256
                : JWSAlgorithm.ES256;
    }

    private void checkRedirectURI(AuthenticationRequest authRequest, String requestBodyRedirectUri)
            throws InvalidRedirectUriException {
        var authRequestRedirectURI = authRequest.getRedirectionURI().toString();
        if (!authRequestRedirectURI.equals(requestBodyRedirectUri)) {
            LOG.warn(
                    "Redirect URI for auth request ({}) does not match redirect URI for request body ({})",
                    authRequestRedirectURI,
                    requestBodyRedirectUri);
            throw new InvalidRedirectUriException(OAuth2Error.INVALID_GRANT);
        }
    }

    private OIDCClaimsRequest getClaimsRequest(AuthenticationRequest authRequest) {
        OIDCClaimsRequest claimsRequest = null;
        if (Objects.nonNull(authRequest.getOIDCClaims())) {
            claimsRequest = authRequest.getOIDCClaims();
        }
        return claimsRequest;
    }

    private OIDCTokenResponse getTokenResponse(
            ClientSession clientSession,
            ClientRegistry clientRegistry,
            AuthenticationRequest authRequest,
            JWSAlgorithm signingAlgorithm,
            AuthCodeExchangeData authCodeExchangeData) {
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        if (authRequest.getNonce() != null) {
            additionalTokenClaims.put("nonce", authRequest.getNonce());
        }

        VtrList vtr = clientSession.getVtrList();
        var credentialTrustLevel = vtr.getCredentialTrustLevel();
        final OIDCClaimsRequest finalClaimsRequest = getClaimsRequest(authRequest);

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
                                            finalClaimsRequest,
                                            true,
                                            signingAlgorithm,
                                            authCodeExchangeData.getClientSessionId(),
                                            credentialTrustLevel));
        } else {
            UserProfile userProfile =
                    dynamoService.getUserProfileByEmail(authCodeExchangeData.getEmail());
            Subject rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            clientRegistry,
                            dynamoService,
                            configurationService.getInternalSectorURI());
            Subject internalPairwiseSubject =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                            userProfile,
                            configurationService.getInternalSectorURI(),
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
                                            finalClaimsRequest,
                                            false,
                                            signingAlgorithm,
                                            authCodeExchangeData.getClientSessionId(),
                                            credentialTrustLevel));
        }
        return tokenResponse;
    }

    private APIGatewayProxyResponseEvent generateInvalidGrantCodeApiGatewayProxyResponse() {
        return generateApiGatewayProxyResponse(
                400,
                new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                        .toJSONObject()
                        .toJSONString());
    }
}
