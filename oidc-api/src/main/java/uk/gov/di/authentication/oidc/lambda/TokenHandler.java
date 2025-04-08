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
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.InvalidRedirectUriException;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthUnsupportedMethodException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
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
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SUCCESSFUL_TOKEN_ISSUED;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.logIfClientSessionsAreNotEqual;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(TokenHandler.class);

    private final TokenService tokenService;
    private final DynamoService dynamoService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final OrchAuthCodeService orchAuthCodeService;
    private final ClientSessionService clientSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final TokenValidationService tokenValidationService;
    private final RedisConnectionService redisConnectionService;
    private final TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final Json objectMapper = SerializationService.getInstance();

    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";

    public TokenHandler(
            TokenService tokenService,
            DynamoService dynamoService,
            ConfigurationService configurationService,
            AuthorisationCodeService authorisationCodeService,
            OrchAuthCodeService orchAuthCodeService,
            ClientSessionService clientSessionService,
            OrchClientSessionService orchClientSessionService,
            TokenValidationService tokenValidationService,
            RedisConnectionService redisConnectionService,
            TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.tokenService = tokenService;
        this.dynamoService = dynamoService;
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.orchAuthCodeService = orchAuthCodeService;
        this.clientSessionService = clientSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.redisConnectionService = redisConnectionService;
        this.tokenClientAuthValidatorFactory = tokenClientAuthValidatorFactory;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public TokenHandler(ConfigurationService configurationService) {
        var kms = new KmsConnectionService(configurationService);
        var oidcApi = new OidcAPI(configurationService);

        this.configurationService = configurationService;
        this.redisConnectionService = new RedisConnectionService(configurationService);
        this.tokenService =
                new TokenService(configurationService, this.redisConnectionService, kms, oidcApi);
        this.dynamoService = new DynamoService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService, redisConnectionService, objectMapper);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(configurationService, kms), configurationService);
        this.tokenClientAuthValidatorFactory =
                new TokenClientAuthValidatorFactory(
                        new DynamoClientService(configurationService),
                        new ClientSignatureValidationService(configurationService));
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
    }

    public TokenHandler(ConfigurationService configurationService, RedisConnectionService redis) {
        var kms = new KmsConnectionService(configurationService);
        var oidcApi = new OidcAPI(configurationService);

        this.configurationService = configurationService;
        this.redisConnectionService = redis;
        this.tokenService =
                new TokenService(configurationService, this.redisConnectionService, kms, oidcApi);
        this.dynamoService = new DynamoService(configurationService);
        this.authorisationCodeService =
                new AuthorisationCodeService(
                        configurationService, redisConnectionService, objectMapper);
        this.orchAuthCodeService = new OrchAuthCodeService(configurationService);
        this.clientSessionService =
                new ClientSessionService(configurationService, redisConnectionService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        new JwksService(configurationService, kms), configurationService);
        this.tokenClientAuthValidatorFactory =
                new TokenClientAuthValidatorFactory(
                        new DynamoClientService(configurationService),
                        new ClientSignatureValidationService(configurationService));
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
    }

    public TokenHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), () -> tokenRequestHandler(input));
    }

    public APIGatewayProxyResponseEvent tokenRequestHandler(APIGatewayProxyRequestEvent input) {
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

        try {
            Optional<AuthCodeExchangeData> orchAuthCodeExchangeDataMaybe =
                    orchAuthCodeService.getExchangeDataForCode(requestBody.get("code"));

            /*
                TODO: ATO-1205:
                 - Need to rethrow exceptions (as RuntimeException?) or return a 500 api gateway proxy response ourselves.
                 - Update the log in the catch clause to be level 'error' and remove Redis references (as by this point the DynamoDB store will be the primary).
                 - Following the above updates, ensure the unit test which ensures unchecked exceptions are caught during consistency checks is updated.
            */
        } catch (Exception e) {
            LOG.warn(
                    "Failed to retrieve authorisation code from orch auth code DynamoDB store. NOTE: Redis is still the primary at present. Error: {}",
                    e.getMessage());
        }

        if (!Objects.equals(authCodeExchangeData.getClientId(), clientRegistry.getClientID())) {
            LOG.warn("Client ID from auth code does not match client ID from request body");
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, authCodeExchangeData.getClientSessionId());
        updateAttachedLogFieldToLogs(
                GOVUK_SIGNIN_JOURNEY_ID, authCodeExchangeData.getClientSessionId());

        var clientSessionId = authCodeExchangeData.getClientSessionId();
        var clientSessionOpt = clientSessionService.getClientSession(clientSessionId);
        if (clientSessionOpt.isEmpty()) {
            LOG.warn("No client session found for auth code client session id");
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        var clientSession = clientSessionOpt.get();
        var orchClientSessionOpt = orchClientSessionService.getClientSession(clientSessionId);
        if (orchClientSessionOpt.isEmpty()) {
            LOG.warn("No orch client session found for auth code client session id");
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        var orchClientSession = orchClientSessionOpt.get();
        logIfClientSessionsAreNotEqual(clientSession, orchClientSession);
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(orchClientSession.getAuthRequestParams());
            checkRedirectURI(authRequest, requestBody.get("redirect_uri"));
        } catch (ParseException e) {
            LOG.warn("Could not parse authentication request from clientRegistry session", e);
            throw new RuntimeException(
                    format(
                            "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                            orchClientSession.getAuthRequestParams(), e));
        } catch (InvalidRedirectUriException e) {
            return generateApiGatewayProxyResponse(
                    400, e.getErrorObject().toJSONObject().toJSONString());
        }

        // ATO-1372: add logging to see how many RPs are sending the correct code verifiers
        var codeChallenge = authRequest.getCodeChallenge();
        var codeVerifierString = requestBody.get("code_verifier");

        try {
            if (!isPKCEValid(
                    Optional.ofNullable(codeChallenge), Optional.ofNullable(codeVerifierString))) {
                LOG.info("PKCE validation failed");
            } else {
                LOG.info("PKCE validation passed");
            }
        } catch (Exception e) {
            LOG.info("PKCE FAILED {}", e.getMessage());
        }

        if (configurationService.isPkceEnabled()) {
            if (!isPKCEValid(
                    Optional.ofNullable(codeChallenge), Optional.ofNullable(codeVerifierString))) {
                return generateInvalidGrantPKCEVerificationCodeApiGatewayProxyResponse();
            }
        }

        var tokenResponse =
                getTokenResponse(
                        orchClientSession,
                        clientRegistry,
                        authRequest,
                        getSigningAlgorithm(clientRegistry),
                        authCodeExchangeData);

        var idTokenHint = tokenResponse.getOIDCTokens().getIDToken().serialize();
        clientSessionService.updateStoredClientSession(
                clientSessionId, clientSession.setIdTokenHint(idTokenHint));
        orchClientSessionService.updateStoredClientSession(
                orchClientSession.withIdTokenHint(idTokenHint));

        var dimensions =
                new HashMap<>(
                        Map.of(
                                ENVIRONMENT.getValue(), configurationService.getEnvironment(),
                                CLIENT.getValue(), clientRegistry.getClientID()));
        cloudwatchMetricsService.incrementCounter(SUCCESSFUL_TOKEN_ISSUED.getValue(), dimensions);

        LOG.info("Successfully generated tokens");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }

    private static boolean isPKCEValid(
            Optional<CodeChallenge> codeChallengeOpt, Optional<String> codeVerifierOpt) {

        if (codeChallengeOpt.isEmpty() && codeVerifierOpt.isEmpty()) {
            LOG.info("No PKCE parameters in request");
            return true;
        } else if (codeChallengeOpt.isEmpty()) {
            LOG.warn("Code verifier present in request but no code_challenge in auth request");
            return false;
        } else if (codeVerifierOpt.isEmpty()) {
            LOG.warn("Code challenge in auth request but no code verifier in token request");
            return false;
        }

        CodeVerifier codeVerifier;
        CodeChallenge codeChallenge = codeChallengeOpt.get();
        try {
            // Throws IllegalArgumentException for invalid verifier
            // Validates the verifier according to spec:
            // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            codeVerifier = new CodeVerifier(codeVerifierOpt.get());
        } catch (IllegalArgumentException e) {
            LOG.warn("Invalid Code Verifier: {}", e.getMessage());
            return false;
        }

        var computedCodeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
        return computedCodeChallenge.getValue().equals(codeChallenge.getValue());
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
            return generateInvalidGrantCodeRefreshTokenApiGatewayProxyResponse();
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
            return generateInvalidGrantCodeRefreshTokenApiGatewayProxyResponse();
        }
        if (!tokenStore.getRefreshToken().equals(currentRefreshToken.getValue())) {
            LOG.warn("Refresh token store does not contain Refresh token in request");
            return generateInvalidGrantCodeRefreshTokenApiGatewayProxyResponse();
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

    private OIDCClaimsRequest getClaimsRequest(
            VectorOfTrust vtr, AuthenticationRequest authRequest) {
        OIDCClaimsRequest claimsRequest = null;
        if (Objects.nonNull(vtr.getLevelOfConfidence())
                && !(vtr.getLevelOfConfidence().equals(NONE))
                && Objects.nonNull(authRequest.getOIDCClaims())) {
            claimsRequest = authRequest.getOIDCClaims();
        }
        return claimsRequest;
    }

    private OIDCTokenResponse getTokenResponse(
            OrchClientSessionItem orchClientSessionItem,
            ClientRegistry clientRegistry,
            AuthenticationRequest authRequest,
            JWSAlgorithm signingAlgorithm,
            AuthCodeExchangeData authCodeExchangeData) {
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        if (authRequest.getNonce() != null) {
            additionalTokenClaims.put("nonce", authRequest.getNonce());
        }

        VectorOfTrust vtr = VectorOfTrust.orderVtrList(orchClientSessionItem.getVtrList()).get(0);
        String vot = vtr.retrieveVectorOfTrustForToken();

        final OIDCClaimsRequest finalClaimsRequest = getClaimsRequest(vtr, authRequest);

        OIDCTokenResponse tokenResponse;
        if (isDocCheckingAppUserWithSubjectId(orchClientSessionItem)) {
            var clientDocAppSubjectId = new Subject(orchClientSessionItem.getDocAppSubjectId());
            tokenResponse =
                    segmentedFunctionCall(
                            "generateTokenResponse",
                            () ->
                                    tokenService.generateTokenResponse(
                                            clientRegistry.getClientID(),
                                            clientDocAppSubjectId,
                                            authRequest.getScope(),
                                            additionalTokenClaims,
                                            clientDocAppSubjectId,
                                            clientDocAppSubjectId,
                                            finalClaimsRequest,
                                            true,
                                            signingAlgorithm,
                                            authCodeExchangeData.getClientSessionId(),
                                            vot,
                                            null));
        } else {
            UserProfile userProfile =
                    dynamoService.getUserProfileByEmail(authCodeExchangeData.getEmail());
            Subject rpPairwiseSubject =
                    ClientSubjectHelper.getSubject(
                            userProfile,
                            clientRegistry,
                            dynamoService,
                            configurationService.getInternalSectorURI());

            LOG.info(
                    "is correct pairwiseId for client the same on clientSession as calculated: {}",
                    Objects.equals(
                            rpPairwiseSubject.getValue(),
                            orchClientSessionItem.getCorrectPairwiseIdGivenSubjectType(
                                    clientRegistry.getSubjectType())));

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
                                            vot,
                                            authCodeExchangeData.getAuthTime()));
        }
        return tokenResponse;
    }

    private APIGatewayProxyResponseEvent
            generateInvalidGrantCodeRefreshTokenApiGatewayProxyResponse() {
        return generateInvalidGrantCodeApiGatewayProxyResponse("Invalid Refresh token");
    }

    private APIGatewayProxyResponseEvent
            generateInvalidGrantPKCEVerificationCodeApiGatewayProxyResponse() {
        return generateInvalidGrantCodeApiGatewayProxyResponse("PKCE code verification failed");
    }

    private APIGatewayProxyResponseEvent generateInvalidGrantCodeApiGatewayProxyResponse(
            String description) {
        return generateApiGatewayProxyResponse(
                400,
                new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, description)
                        .toJSONObject()
                        .toJSONString());
    }
}
