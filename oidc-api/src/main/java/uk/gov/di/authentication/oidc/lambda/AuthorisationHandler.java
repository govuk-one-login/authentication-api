package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.jetbrains.annotations.Nullable;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.entity.ClientRateLimitConfig;
import uk.gov.di.authentication.oidc.entity.SlidingWindowAlgorithm;
import uk.gov.di.authentication.oidc.exceptions.IncorrectRedirectUriException;
import uk.gov.di.authentication.oidc.exceptions.InvalidAuthenticationRequestException;
import uk.gov.di.authentication.oidc.exceptions.InvalidHttpMethodException;
import uk.gov.di.authentication.oidc.exceptions.MissingClientIDException;
import uk.gov.di.authentication.oidc.exceptions.MissingRedirectUriException;
import uk.gov.di.authentication.oidc.helpers.RequestObjectToAuthRequestHelper;
import uk.gov.di.authentication.oidc.services.AuthorisationService;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.authentication.oidc.services.RateLimitService;
import uk.gov.di.authentication.oidc.validators.QueryParamsAuthorizeValidator;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.conditions.DocAppUserHelper;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.InvalidResponseModeException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.DocAppSubjectIdHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static com.nimbusds.oauth2.sdk.OAuth2Error.INVALID_REQUEST;
import static com.nimbusds.oauth2.sdk.OAuth2Error.SERVER_ERROR;
import static com.nimbusds.oauth2.sdk.OAuth2Error.UNAUTHORIZED_CLIENT_CODE;
import static com.nimbusds.oauth2.sdk.OAuth2Error.VALIDATION_FAILED;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static java.util.Objects.isNull;
import static uk.gov.di.authentication.oidc.helpers.AuthRequestHelper.getCustomParameterOpt;
import static uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService.VTR_PARAM;
import static uk.gov.di.orchestration.shared.conditions.IdentityHelper.identityRequired;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.attachTxmaAuditFieldFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LocaleHelper.getPrimaryLanguageFromUILocales;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachOrchSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.updateAttachedSessionIdToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthorisationHandler.class);
    public static final String GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY = "result";

    private final ConfigurationService configurationService;
    private final OrchSessionService orchSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final QueryParamsAuthorizeValidator queryParamsAuthorizeValidator;
    private final RequestObjectAuthorizeValidator requestObjectAuthorizeValidator;
    private final AuditService auditService;
    private final ClientService clientService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final DocAppAuthorisationService docAppAuthorisationService;
    private final NoSessionOrchestrationService noSessionOrchestrationService;
    private final TokenValidationService tokenValidationService;
    private final AuthFrontend authFrontend;
    private final AuthorisationService authorisationService;
    private final RateLimitService rateLimitService;

    public AuthorisationHandler(
            ConfigurationService configurationService,
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            AuditService auditService,
            QueryParamsAuthorizeValidator queryParamsAuthorizeValidator,
            RequestObjectAuthorizeValidator requestObjectAuthorizeValidator,
            ClientService clientService,
            DocAppAuthorisationService docAppAuthorisationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            NoSessionOrchestrationService noSessionOrchestrationService,
            TokenValidationService tokenValidationService,
            AuthFrontend authFrontend,
            AuthorisationService authorisationService,
            RateLimitService rateLimitService) {
        this.configurationService = configurationService;
        this.orchSessionService = orchSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.auditService = auditService;
        this.queryParamsAuthorizeValidator = queryParamsAuthorizeValidator;
        this.requestObjectAuthorizeValidator = requestObjectAuthorizeValidator;
        this.clientService = clientService;
        this.docAppAuthorisationService = docAppAuthorisationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.noSessionOrchestrationService = noSessionOrchestrationService;
        this.tokenValidationService = tokenValidationService;
        this.authFrontend = authFrontend;
        this.authorisationService = authorisationService;
        this.rateLimitService = rateLimitService;
    }

    public AuthorisationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        var kmsConnectionService = new KmsConnectionService(configurationService);
        var jwksService = new JwksService(configurationService, kmsConnectionService);
        var stateStorageService = new StateStorageService(configurationService);
        this.orchSessionService = new OrchSessionService(configurationService);
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(
                        configurationService,
                        kmsConnectionService,
                        noSessionOrchestrationService,
                        stateStorageService);
        this.auditService = new AuditService(configurationService);
        this.queryParamsAuthorizeValidator =
                new QueryParamsAuthorizeValidator(configurationService);
        this.requestObjectAuthorizeValidator =
                new RequestObjectAuthorizeValidator(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        this.docAppAuthorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        kmsConnectionService,
                        jwksService,
                        stateStorageService);
        var cloudwatchMetricService = new CloudwatchMetricsService(configurationService);
        this.cloudwatchMetricsService = cloudwatchMetricService;
        this.tokenValidationService = new TokenValidationService(jwksService, configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
        this.authorisationService = new AuthorisationService(configurationService);
        var slidingWindowAlgorithm = new SlidingWindowAlgorithm(configurationService);
        this.rateLimitService =
                new RateLimitService(slidingWindowAlgorithm, cloudwatchMetricService);
    }

    public AuthorisationHandler(
            ConfigurationService configurationService, RedisConnectionService redis) {
        this.configurationService = configurationService;
        this.orchSessionService = new OrchSessionService(configurationService);
        this.orchClientSessionService = new OrchClientSessionService(configurationService);
        this.orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.queryParamsAuthorizeValidator =
                new QueryParamsAuthorizeValidator(configurationService);
        this.requestObjectAuthorizeValidator =
                new RequestObjectAuthorizeValidator(configurationService);
        this.clientService = new DynamoClientService(configurationService);
        var kmsConnectionService = new KmsConnectionService(configurationService);
        var jwksService = new JwksService(configurationService, kmsConnectionService);
        var stateStorageService = new StateStorageService(configurationService);
        this.docAppAuthorisationService =
                new DocAppAuthorisationService(
                        configurationService,
                        kmsConnectionService,
                        jwksService,
                        stateStorageService);
        var cloudwatchMetricService = new CloudwatchMetricsService(configurationService);
        this.cloudwatchMetricsService = cloudwatchMetricService;
        this.noSessionOrchestrationService =
                new NoSessionOrchestrationService(configurationService, redis);
        this.tokenValidationService = new TokenValidationService(jwksService, configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
        this.authorisationService = new AuthorisationService(configurationService);
        this.rateLimitService =
                new RateLimitService(
                        new SlidingWindowAlgorithm(configurationService), cloudwatchMetricService);
    }

    public AuthorisationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        attachTraceId();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> authoriseRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authoriseRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) throws java.text.ParseException {
        var persistentSessionId =
                orchestrationAuthorizationService.getExistingOrCreateNewPersistentSessionId(
                        input.getHeaders());
        var ipAddress = IpAddressHelper.extractIpAddress(input);
        var clientSessionId = IdGenerator.generate();
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
        attachTxmaAuditFieldFromHeaders(input.getHeaders());

        var user =
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId);

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED, AuditService.UNKNOWN, user);
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);
        LOG.info("Received authentication request");

        AuthenticationRequest authRequest;
        try {
            if (!"GET".equals(input.getHttpMethod())) {
                LOG.warn(
                        String.format(
                                "Authentication request sent with invalid HTTP method %s",
                                input.getHttpMethod()));
                throw new InvalidHttpMethodException(
                        String.format(
                                "Authentication request does not support %s requests",
                                input.getHttpMethod()));
            }
            Map<String, String> parameterMap = input.getQueryStringParameters();
            Map<String, List<String>> requestParameters =
                    parameterMap.entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey, entry -> List.of(entry.getValue())));
            authRequest = AuthenticationRequest.parse(requestParameters);
            authRequest = stripOutReauthenticateQueryParams(authRequest);
            authRequest = stripOutLoginHintQueryParams(authRequest);
        } catch (ParseException e) {
            LOG.warn("Authentication request could not be parsed", e);
            return generateParseExceptionResponse(e, user);
        } catch (NullPointerException e) {
            LOG.warn(
                    "No parameters are present in the Authentication request query string or body",
                    e);
            return generateMissingParametersResponse(
                    user,
                    "No parameters are present in the Authentication request query string or body",
                    null);
        }

        ClientRegistry client;
        String clientId = authRequest.getClientID().getValue();
        try {
            client =
                    clientService
                            .getClient(clientId)
                            .orElseThrow(() -> new ClientNotFoundException(clientId));
            updateAttachedLogFieldToLogs(CLIENT_ID, clientId);
        } catch (ClientNotFoundException e) {
            return generateBadRequestResponse(user, e.getMessage(), clientId);
        }

        Optional<AuthRequestError> authRequestError;
        boolean isJarValidationRequired =
                orchestrationAuthorizationService.isJarValidationRequired(client);
        if (isJarValidationRequired && authRequest.getRequestObject() == null) {
            String errorMsg = "JAR required for client but request does not contain Request Object";
            LOG.warn(errorMsg);
            if (client.getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
                LOG.warn("Redirecting");
                return generateErrorResponse(
                        authRequest.getRedirectionURI(),
                        authRequest.getState(),
                        authRequest.getResponseMode(),
                        new ErrorObject(ACCESS_DENIED_CODE, errorMsg),
                        client.getClientID(),
                        user);
            } else {
                LOG.warn("Redirect URI {} is invalid for client", authRequest.getRedirectionURI());
                return generateBadRequestResponse(user, errorMsg, client.getClientID());
            }
        }

        if (configurationService.isRpRateLimitingEnabled()) {
            var rateLimitDecision =
                    rateLimitService.getClientRateLimitDecision(
                            ClientRateLimitConfig.fromClientRegistry(client));

            if (rateLimitDecision.hasExceededRateLimit()) {
                switch (rateLimitDecision.getAction()) {
                    case RETURN_TO_RP -> {
                        // ATO-1783: return an oAuth Error here to say unavailable
                    }
                    case NONE -> {
                        // continue
                    }
                }
            }
        }

        try {
            if (authRequest.getRequestObject() == null) {
                LOG.info("Validating request query params");
                authRequestError = queryParamsAuthorizeValidator.validate(authRequest);
            } else {
                LOG.info("Validating request object");
                authRequestError = requestObjectAuthorizeValidator.validate(authRequest);
            }
        } catch (ClientRedirectUriValidationException | InvalidResponseModeException e) {
            return generateBadRequestResponse(user, e.getMessage(), client.getClientID());
        } catch (ClientSignatureValidationException e) {
            return generateApiGatewayProxyResponse(
                    VALIDATION_FAILED.getHTTPStatusCode(), VALIDATION_FAILED.getDescription());
        } catch (JwksException e) {
            return generateApiGatewayProxyResponse(
                    SERVER_ERROR.getHTTPStatusCode(), SERVER_ERROR.getDescription());
        }

        if (!client.isActive()) {
            LOG.error("Client configured as not active in Client Registry");
            return generateErrorResponse(
                    authRequest.getRedirectionURI(),
                    authRequest.getState(),
                    authRequest.getResponseMode(),
                    new ErrorObject(UNAUTHORIZED_CLIENT_CODE, "client deactivated"),
                    authRequest.getClientID().getValue(),
                    user);
        }

        if (authRequestError.isPresent()) {
            return generateErrorResponse(
                    authRequestError.get().redirectURI(),
                    authRequestError.get().state(),
                    authRequest.getResponseMode(),
                    authRequestError.get().errorObject(),
                    authRequest.getClientID().getValue(),
                    user);
        }
        authRequest = RequestObjectToAuthRequestHelper.transform(authRequest);

        try {
            cloudwatchMetricsService.putEmbeddedValue(
                    "rpStateLength",
                    authRequest.getState().getValue().length(),
                    Map.of("clientId", authRequest.getClientID().getValue()));
        } catch (Exception e) {
            LOG.warn("Error recording state length, continuing: ", e);
        }

        boolean reauthRequested =
                getCustomParameterOpt(authRequest, "id_token_hint").isPresent()
                        && authRequest.getPrompt() != null
                        && authRequest.getPrompt().contains(Prompt.Type.LOGIN);
        var vtrList = getVtrList(reauthRequested, authRequest);
        var requestedVtr = VectorOfTrust.getLowestVtr(vtrList);

        sendAuthRequestParsedAuditEvent(authRequest, client, reauthRequested, requestedVtr, user);

        Optional<String> sessionId =
                CookieHelper.getSessionIdFromRequestHeaders(input.getHeaders());
        Optional<OrchSessionItem> orchSessionOptional =
                sessionId.flatMap(orchSessionService::getSession);

        var creationDate = LocalDateTime.now();
        OrchClientSessionItem orchClientSession =
                orchClientSessionService.generateClientSession(
                        clientSessionId,
                        authRequest.toParameters(),
                        creationDate,
                        vtrList,
                        client.getClientName());

        if (DocAppUserHelper.isDocCheckingAppUser(
                authRequest.toParameters(), Optional.of(client))) {

            return handleDocAppJourney(
                    orchSessionOptional,
                    orchClientSession,
                    authRequest,
                    client,
                    clientSessionId,
                    persistentSessionId,
                    user);
        }

        Optional<String> browserSessionIdFromCookie =
                CookieHelper.parseBrowserSessionCookie(input.getHeaders());

        return handleAuthJourney(
                sessionId,
                browserSessionIdFromCookie,
                orchSessionOptional,
                orchClientSession,
                authRequest,
                persistentSessionId,
                client,
                clientSessionId,
                reauthRequested,
                requestedVtr,
                user);
    }

    private void sendAuthRequestParsedAuditEvent(
            AuthenticationRequest authRequest,
            ClientRegistry client,
            boolean reauthRequested,
            VectorOfTrust requestedVtr,
            TxmaAuditUser user) {
        var identityRequested =
                identityRequired(
                        authRequest.toParameters(),
                        client.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());

        var auditEventExtensions =
                new ArrayList<>(
                        List.of(
                                pair("rpSid", getRpSid(authRequest)),
                                pair("identityRequested", identityRequested),
                                pair("reauthRequested", reauthRequested),
                                pair(
                                        "credential_trust_level",
                                        requestedVtr.getCredentialTrustLevel().toString())));

        var maxAgeParam = getMaxAge(authRequest);
        if (configurationService.supportMaxAgeEnabled()
                && client.getMaxAgeEnabled()
                && maxAgeParam.isPresent()) {
            auditEventExtensions.add(pair("maximumSessionAge", maxAgeParam.get()));
        }

        getCustomParameterOpt(authRequest, "channel")
                .ifPresent(channel -> auditEventExtensions.add(pair("channel", channel)));

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_PARSED,
                authRequest.getClientID().getValue(),
                user,
                auditEventExtensions.toArray(AuditService.MetadataPair[]::new));
    }

    private static String getRpSid(AuthenticationRequest authRequest) {
        try {
            return getCustomParameterOpt(authRequest, "rp_sid").orElse(AuditService.UNKNOWN);
        } catch (Exception e) {
            LOG.error("Failed to retrieve rp_sid. Passing unknown");
            return AuditService.UNKNOWN;
        }
    }

    private List<VectorOfTrust> getVtrList(
            boolean reauthRequested, AuthenticationRequest authRequest)
            throws java.text.ParseException {
        if (reauthRequested && isNull(authRequest.getCustomParameter(VTR_PARAM))) {
            var idTokenHint =
                    SignedJWT.parse(authRequest.getCustomParameter("id_token_hint").get(0));
            var grantedVectorOfTrust = extractVoTFromIdTokenHint(idTokenHint);
            return List.of(grantedVectorOfTrust);
        }
        return orchestrationAuthorizationService.getVtrList(authRequest);
    }

    private VectorOfTrust extractVoTFromIdTokenHint(SignedJWT idTokenHint)
            throws java.text.ParseException {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                        extractVoTStringListFromIdTokenHint(idTokenHint))
                .get(0);
    }

    private List<String> extractVoTStringListFromIdTokenHint(SignedJWT idTokenHint)
            throws java.text.ParseException {
        var votClaim = idTokenHint.getJWTClaimsSet().getClaim("vot");
        if (votClaim == null) {
            return List.of(CredentialTrustLevel.getDefault().getValue());
        } else if (votClaim instanceof String vot) {
            return List.of(vot);
        }
        throw new java.text.ParseException("vtr is in an invalid format. Could not be parsed.", 0);
    }

    private APIGatewayProxyResponseEvent handleDocAppJourney(
            Optional<OrchSessionItem> orchSessionOptional,
            OrchClientSessionItem orchClientSession,
            AuthenticationRequest authenticationRequest,
            ClientRegistry client,
            String clientSessionId,
            String persistentSessionId,
            TxmaAuditUser user) {
        var newSessionId = IdGenerator.generate();
        var newBrowserSessionId = IdGenerator.generate();
        OrchSessionItem orchSession;
        if (orchSessionOptional.isEmpty()) {
            orchSession =
                    new OrchSessionItem(newSessionId).withBrowserSessionId(newBrowserSessionId);
            LOG.info("Created new Orch session with ID {}", newSessionId);
        } else {
            String previousOrchSessionId = orchSessionOptional.get().getSessionId();
            orchSession =
                    orchSessionService.addOrUpdateSessionId(
                            Optional.of(previousOrchSessionId), newSessionId);
            LOG.info("Updated Orch session ID from {} to {}", previousOrchSessionId, newSessionId);
        }
        updateAttachedSessionIdToLogs(newSessionId);
        attachOrchSessionIdToLogs(orchSession.getSessionId());

        Subject subjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(
                        authenticationRequest.toParameters(),
                        configurationService.isCustomDocAppClaimEnabled(),
                        configurationService.getDocAppDomain());
        LOG.info("Doc app request received");

        orchClientSessionService.storeClientSession(
                orchClientSession.withDocAppSubjectId(subjectId.getValue()));
        LOG.info("Subject saved to ClientSession for DocCheckingAppUser");

        orchSession.addClientSession(clientSessionId);
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        updateAttachedLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
        orchSessionOptional.ifPresentOrElse(
                s -> orchSessionService.updateSession(orchSession),
                () -> orchSessionService.addSession(orchSession));
        LOG.info("Session saved successfully");

        var state = new State();
        var encryptedJWT =
                docAppAuthorisationService.constructRequestJWT(
                        state, orchClientSession.getDocAppSubjectId(), client, clientSessionId);
        var authRequestBuilder =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getDocAppAuthorisationClientId()))
                        .endpointURI(configurationService.getDocAppAuthorisationURI())
                        .requestObject(encryptedJWT);

        var authorisationRequest = authRequestBuilder.build();

        docAppAuthorisationService.storeState(newSessionId, state);
        noSessionOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);

        auditService.submitAuditEvent(
                DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED,
                client.getClientID(),
                user.withSessionId(newSessionId)
                        .withUserId(orchClientSession.getDocAppSubjectId()));

        URI authorisationRequestUri = authorisationRequest.toURI();
        LOG.info(
                "AuthorisationHandler successfully processed doc app request, redirect URI {}",
                authorisationRequestUri);

        cloudwatchMetricsService.incrementCounter(
                "DocAppHandoff", Map.of("Environment", configurationService.getEnvironment()));

        List<String> cookies =
                handleCookies(
                        newSessionId,
                        orchSession,
                        authenticationRequest,
                        persistentSessionId,
                        clientSessionId);

        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, authorisationRequestUri.toString()),
                Map.of(ResponseHeaders.SET_COOKIE, cookies));
    }

    private APIGatewayProxyResponseEvent handleAuthJourney(
            Optional<String> previousSessionIdFromCookie,
            Optional<String> browserSessionIdFromCookie,
            Optional<OrchSessionItem> existingOrchSessionOptional,
            OrchClientSessionItem orchClientSession,
            AuthenticationRequest authenticationRequest,
            String persistentSessionId,
            ClientRegistry client,
            String clientSessionId,
            boolean reauthRequested,
            VectorOfTrust requestedVtr,
            TxmaAuditUser user) {
        if (Objects.nonNull(authenticationRequest.getPrompt())
                && authenticationRequest.getPrompt().contains(Prompt.Type.SELECT_ACCOUNT)) {
            return generateErrorResponse(
                    authenticationRequest.getRedirectionURI(),
                    authenticationRequest.getState(),
                    authenticationRequest.getResponseMode(),
                    OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
                    authenticationRequest.getClientID().getValue(),
                    user);
        }

        Optional<String> browserSessionIdFromSession =
                existingOrchSessionOptional.map(OrchSessionItem::getBrowserSessionId);
        boolean doesBrowserSessionIdFromSessionNotMatchCookie =
                browserSessionIdFromSession.isPresent()
                        && !Objects.equals(browserSessionIdFromSession, browserSessionIdFromCookie);

        OrchSessionItem orchSession;
        var newSessionId = IdGenerator.generate();
        var newBrowserSessionId = IdGenerator.generate();
        if (previousSessionIdFromCookie.isEmpty()
                || existingOrchSessionOptional.isEmpty()
                || doesBrowserSessionIdFromSessionNotMatchCookie) {
            orchSession = createNewOrchSession(newSessionId, newBrowserSessionId);
            LOG.info("Created session with id: {}", newSessionId);
            // We re-assign here to ensure that we only pass auth previous session id
            // When there is a previous session present (ie hasn't logged out or expired)
            previousSessionIdFromCookie = Optional.empty();
        } else {
            var maxAgeParam = getMaxAge(authenticationRequest);
            boolean isMaxAgeSupported =
                    configurationService.supportMaxAgeEnabled() && client.getMaxAgeEnabled();
            final long timeNow = NowHelper.now().toInstant().getEpochSecond();

            if (maxAgeParam.isPresent()
                    && isMaxAgeSupported
                    && maxAgeExpired(
                            existingOrchSessionOptional.get().getAuthTime(),
                            maxAgeParam,
                            timeNow)) {
                var newSessionIdForPreviousSession = IdGenerator.generate();

                orchSession =
                        updateOrchSessionDueToMaxAgeExpiry(
                                newSessionId,
                                newBrowserSessionId,
                                existingOrchSessionOptional.get(),
                                timeNow,
                                newSessionIdForPreviousSession);

                LOG.info(
                        "Updated previous Orch and shared session ID due to max age expiry. Session ID updated from {} to {}",
                        existingOrchSessionOptional.get().getSessionId(),
                        newSessionIdForPreviousSession);

                LOG.info(
                        "Created new Orch and shared sessions with session ID {} due to max age expiry",
                        newSessionId);

            } else {
                var previousSessionId = previousSessionIdFromCookie.get();

                orchSession =
                        updateOrchSession(newSessionId, existingOrchSessionOptional.get(), timeNow);

                LOG.info(
                        "Updated existing session ID from {} to {}",
                        previousSessionId,
                        newSessionId);
            }
        }

        attachSessionIdToLogs(newSessionId);
        attachOrchSessionIdToLogs(orchSession.getSessionId());

        user = user.withSessionId(newSessionId);
        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_INITIATED,
                authenticationRequest.getClientID().getValue(),
                user,
                pair("client-name", client.getClientName()),
                pair("new_authentication_required", doesBrowserSessionIdFromSessionNotMatchCookie));

        orchClientSessionService.storeClientSession(orchClientSession);

        orchSession.addClientSession(clientSessionId);
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        updateAttachedLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
        orchSessionService.addSession(orchSession);
        LOG.info("Session saved successfully");
        return generateAuthRedirect(
                newSessionId,
                clientSessionId,
                authenticationRequest,
                persistentSessionId,
                client,
                reauthRequested,
                requestedVtr,
                user,
                previousSessionIdFromCookie,
                orchSession);
    }

    private OrchSessionItem createNewOrchSession(String sessionId, String browserSessionId) {
        var newOrchSessionItem =
                new OrchSessionItem(sessionId).withBrowserSessionId(browserSessionId);
        LOG.info("Created new Orch session with session ID: {}", sessionId);
        return newOrchSessionItem;
    }

    private OrchSessionItem updateOrchSession(
            String newSessionId, OrchSessionItem previousSession, long timeNow) {
        OrchSessionItem updatedSession =
                new OrchSessionItem(previousSession)
                        .withSessionId(newSessionId)
                        .withTimeToLive(timeNow + configurationService.getSessionExpiry());
        updatedSession.resetProcessingIdentityAttempts();
        orchSessionService.deleteSession(previousSession.getSessionId());
        LOG.info(
                "Updated existing Orch session ID from {} to {}",
                previousSession.getSessionId(),
                newSessionId);
        return updatedSession;
    }

    private OrchSessionItem updateOrchSessionDueToMaxAgeExpiry(
            String newSessionId,
            String newBrowserSessionId,
            OrchSessionItem previousSession,
            long timeNow,
            String newSessionIdForPreviousSession) {
        OrchSessionItem updatedPreviousSession =
                new OrchSessionItem(previousSession)
                        .withSessionId(newSessionIdForPreviousSession)
                        .withTimeToLive(timeNow + configurationService.getSessionExpiry());
        orchSessionService.addSession(updatedPreviousSession);
        orchSessionService.deleteSession(previousSession.getSessionId());

        OrchSessionItem newSession =
                new OrchSessionItem(previousSession)
                        .withSessionId(newSessionId)
                        .withBrowserSessionId(newBrowserSessionId)
                        .withTimeToLive(timeNow + configurationService.getSessionExpiry())
                        .withAuthenticated(false)
                        .withPreviousSessionId(newSessionIdForPreviousSession);
        newSession.resetProcessingIdentityAttempts();
        newSession.resetClientSessions();
        return newSession;
    }

    private Optional<Integer> getMaxAge(AuthenticationRequest authRequest) {
        // We call getMaxAge on both query params and request objects as
        // we've persisted the value to the top level when calling
        // RequestObjectToAuthRequestHelper.transform
        var maxAge = authRequest.getMaxAge();

        if (maxAge == -1) {
            // Nimbus returns -1 for no max_age parameter
            return Optional.empty();
        } else return Optional.of(maxAge);
    }

    private boolean maxAgeExpired(Long authTime, Optional<Integer> maxAge, long timeNow) {
        if (maxAge.isEmpty()) return false;
        if (authTime == null) {
            LOG.warn(
                    "Auth time expected to be set in Orch session but is null. Assuming that max age has not expired.");
            return false;
        }
        if (authTime > timeNow || authTime < 0) {
            LOG.error(
                    "Auth time is negative or greater than current time which implies auth time has been set incorrectly. Assuming that max age has not expired.");
            return false;
        }
        return authTime + maxAge.get() < timeNow;
    }

    private APIGatewayProxyResponseEvent generateAuthRedirect(
            String sessionId,
            String clientSessionId,
            AuthenticationRequest authenticationRequest,
            String persistentSessionId,
            ClientRegistry client,
            boolean reauthRequested,
            VectorOfTrust requestedVtr,
            TxmaAuditUser user,
            Optional<String> previousSessionId,
            OrchSessionItem orchSession) {
        LOG.info("Redirecting");

        Optional<Prompt.Type> prompt =
                Objects.nonNull(authenticationRequest.getPrompt())
                                && authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)
                        ? Optional.of(Prompt.Type.LOGIN)
                        : Optional.empty();

        var googleAnalyticsOpt =
                getCustomParameterOpt(authenticationRequest, GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY);

        var redirectURI = authFrontend.authorizeURI(prompt, googleAnalyticsOpt).toString();

        List<String> cookies =
                handleCookies(
                        sessionId,
                        orchSession,
                        authenticationRequest,
                        persistentSessionId,
                        clientSessionId);

        var jwtID = IdGenerator.generate();
        var expiryDate = NowHelper.nowPlus(3, ChronoUnit.MINUTES);
        var rpSectorIdentifierHost =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        client, configurationService.getInternalSectorURI());
        var state = new State();
        orchestrationAuthorizationService.storeState(sessionId, clientSessionId, state);

        String reauthSub = null;
        String reauthSid = null;
        if (reauthRequested) {
            try {
                SignedJWT reauthIdToken = getReauthIdToken(authenticationRequest);
                reauthSub = reauthIdToken.getJWTClaimsSet().getSubject();
                reauthSid = reauthIdToken.getJWTClaimsSet().getStringClaim("sid");
            } catch (RuntimeException e) {
                return generateErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        authenticationRequest.getState(),
                        authenticationRequest.getResponseMode(),
                        new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, e.getMessage()),
                        authenticationRequest.getClientID().getValue(),
                        user);
            } catch (java.text.ParseException e) {
                LOG.warn("Unable to parse id_token_hint SignedJWT into claims");
                throw new RuntimeException("Invalid id_token_hint");
            }
        }

        var cookieConsentOpt = getCustomParameterOpt(authenticationRequest, "cookie_consent");
        var gaOpt = getCustomParameterOpt(authenticationRequest, "_ga");
        var levelOfConfidenceOpt = Optional.ofNullable(requestedVtr.getLevelOfConfidence());
        var isIdentityRequired =
                identityRequired(
                        authenticationRequest.toParameters(),
                        client.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());
        var channel =
                getCustomParameterOpt(authenticationRequest, "channel")
                        .orElse(client.getChannel())
                        .toLowerCase();
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getOrchestrationClientId())
                        .audience(authFrontend.baseURI().toString())
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .notBeforeTime(NowHelper.now())
                        .jwtID(jwtID)
                        .claim("rp_client_id", client.getClientID())
                        .claim("rp_sector_host", rpSectorIdentifierHost)
                        .claim("rp_redirect_uri", authenticationRequest.getRedirectionURI())
                        .claim("rp_state", authenticationRequest.getState().getValue())
                        .claim("client_name", client.getClientName())
                        .claim("cookie_consent_shared", client.isCookieConsentShared())
                        .claim("is_one_login_service", client.isOneLoginService())
                        .claim("service_type", client.getServiceType())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim(
                                "requested_credential_strength",
                                requestedVtr.getCredentialTrustLevel().getValue())
                        .claim("state", state.getValue())
                        .claim("client_id", configurationService.getOrchestrationClientId())
                        .claim("redirect_uri", configurationService.getOrchestrationRedirectURI())
                        .claim("reauthenticate", reauthSub)
                        .claim("previous_govuk_signin_journey_id", reauthSid)
                        .claim("channel", channel)
                        .claim("authenticated", orchSession.getAuthenticated())
                        .claim("scope", authenticationRequest.getScope().toString())
                        .claim("login_hint", authenticationRequest.getLoginHint())
                        .claim("is_smoke_test", client.isSmokeTest())
                        .claim("subject_type", client.getSubjectType())
                        .claim("is_identity_verification_required", isIdentityRequired);

        previousSessionId.ifPresent(id -> claimsBuilder.claim("previous_session_id", id));
        gaOpt.ifPresent(ga -> claimsBuilder.claim("_ga", ga));
        cookieConsentOpt.ifPresent(
                cookieConsent -> claimsBuilder.claim("cookie_consent", cookieConsent));
        levelOfConfidenceOpt.ifPresent(
                levelOfConfidence ->
                        claimsBuilder.claim(
                                "requested_level_of_confidence", levelOfConfidence.getValue()));

        var claimsSetRequest =
                constructAdditionalAuthenticationClaims(client, authenticationRequest);
        claimsSetRequest.ifPresent(t -> claimsBuilder.claim("claim", t.toJSONString()));
        var encryptedJWT =
                orchestrationAuthorizationService.getSignedAndEncryptedJWT(claimsBuilder.build());

        var authorizationRequest =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getOrchestrationClientId()))
                        .endpointURI(URI.create(redirectURI))
                        .requestObject(encryptedJWT)
                        .build();
        try {
            cloudwatchMetricsService.putEmbeddedValue(
                    "AuthRedirectQueryParamSize",
                    authorizationRequest.toQueryString().length(),
                    Map.of("clientId", client.getClientID()));
        } catch (Exception e) {
            LOG.warn("Error recording query params length, continuing: ", e);
        }

        redirectURI = authorizationRequest.toURI().toString();
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, redirectURI),
                Map.of(ResponseHeaders.SET_COOKIE, cookies));
    }

    private APIGatewayProxyResponseEvent generateBadRequestResponse(
            TxmaAuditUser user, String errorDescription, @Nullable String clientId) {
        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                clientId == null ? AuditService.UNKNOWN : clientId,
                user,
                pair("description", errorDescription));

        LOG.warn("Bad request: {}", errorDescription);

        return generateApiGatewayProxyResponse(
                INVALID_REQUEST.getHTTPStatusCode(), INVALID_REQUEST.getDescription());
    }

    private APIGatewayProxyResponseEvent generateMissingParametersResponse(
            TxmaAuditUser user, String errorDescription, @Nullable String clientId) {
        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                clientId == null ? AuditService.UNKNOWN : clientId,
                user,
                pair("description", errorDescription));
        return generateApiGatewayProxyResponse(400, ErrorResponse.ERROR_1001.getMessage());
    }

    private APIGatewayProxyResponseEvent generateParseExceptionResponse(
            ParseException error, TxmaAuditUser user) {
        try {
            authorisationService.classifyParseException(error);
        } catch (MissingClientIDException e) {
            return generateMissingParametersResponse(user, e.getError().getDescription(), null);
        } catch (MissingRedirectUriException e) {
            return generateMissingParametersResponse(
                    user,
                    e.getError().getDescription(),
                    error.getClientID() != null ? error.getClientID().getValue() : null);
        } catch (IncorrectRedirectUriException | ClientNotFoundException e) {
            return generateBadRequestResponse(user, e.getMessage(), error.getClientID().getValue());
        } catch (InvalidAuthenticationRequestException e) {
            return generateErrorResponse(
                    error.getRedirectionURI(),
                    error.getState(),
                    error.getResponseMode(),
                    INVALID_REQUEST,
                    error.getClientID().getValue(),
                    user);
        }
        throw new AssertionError("Not reached");
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            URI redirectUri,
            State state,
            ResponseMode responseMode,
            ErrorObject errorObject,
            String clientId,
            TxmaAuditUser user) {

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                clientId,
                user,
                pair("description", errorObject.getDescription()));

        LOG.warn(
                "Returning error response: {} {}",
                errorObject.getCode(),
                errorObject.getDescription());
        var error = new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);

        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, error.toURI().toString()), null);
    }

    private Optional<OIDCClaimsRequest> constructAdditionalAuthenticationClaims(
            ClientRegistry clientRegistry, AuthenticationRequest authenticationRequest) {
        LOG.info("Constructing additional authentication claims");
        var identityRequired =
                identityRequired(
                        authenticationRequest.toParameters(),
                        clientRegistry.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());

        var amScopePresent =
                requestedScopesContain(CustomScopeValue.ACCOUNT_MANAGEMENT, authenticationRequest);
        var govukAccountScopePresent =
                requestedScopesContain(CustomScopeValue.GOVUK_ACCOUNT, authenticationRequest);
        var phoneScopePresent = requestedScopesContain(OIDCScopeValue.PHONE, authenticationRequest);
        var emailScopePresent = requestedScopesContain(OIDCScopeValue.EMAIL, authenticationRequest);

        var claimsSet = new HashSet<AuthUserInfoClaims>();
        claimsSet.add(AuthUserInfoClaims.EMAIL);
        claimsSet.add(AuthUserInfoClaims.LOCAL_ACCOUNT_ID);
        claimsSet.add(AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE);
        claimsSet.add(AuthUserInfoClaims.UPLIFT_REQUIRED);
        claimsSet.add(AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH);
        if (identityRequired) {
            LOG.info(
                    "Identity is required. Adding the salt, email_verified and phone_number claims");
            claimsSet.add(AuthUserInfoClaims.SALT);
            // Email required for ID journeys for use in Face-to-Face flows
            claimsSet.add(AuthUserInfoClaims.EMAIL_VERIFIED);
            claimsSet.add(AuthUserInfoClaims.PHONE_NUMBER);
        }
        if (amScopePresent) {
            LOG.info("am scope is present. Adding the public_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.PUBLIC_SUBJECT_ID);
        } else if (PUBLIC.toString().equalsIgnoreCase(clientRegistry.getSubjectType())) {
            LOG.info("client has PUBLIC subjectType. Adding the public_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.PUBLIC_SUBJECT_ID);
        }

        if (govukAccountScopePresent) {
            LOG.info("govuk-account scope is present. Adding the legacy_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.LEGACY_SUBJECT_ID);
        }
        if (phoneScopePresent) {
            LOG.info(
                    "phone scope is present. Adding the phone_number and phone_number_verified claim");
            claimsSet.add(AuthUserInfoClaims.PHONE_NUMBER);
            claimsSet.add(AuthUserInfoClaims.PHONE_VERIFIED);
        }
        if (emailScopePresent) {
            LOG.info("email scope is present. Adding the email_verified claim");
            claimsSet.add(AuthUserInfoClaims.EMAIL_VERIFIED);
        }

        var claimSetEntries =
                claimsSet.stream()
                        .map(claim -> new ClaimsSetRequest.Entry(claim.getValue()))
                        .toList();

        if (claimSetEntries.isEmpty()) {
            LOG.info("No additional claims to add to request");
            return Optional.empty();
        }
        var claimsSetRequest = new ClaimsSetRequest(claimSetEntries);
        return Optional.of(new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest));
    }

    private boolean requestedScopesContain(
            Scope.Value scope, AuthenticationRequest authenticationRequest) {
        return authenticationRequest.getScope().toStringList().contains(scope.getValue());
    }

    private List<String> handleCookies(
            String sessionId,
            OrchSessionItem orchSessionItem,
            AuthenticationRequest authRequest,
            String persistentSessionId,
            String clientSessionId) {
        List<String> cookies = new ArrayList<>();
        cookies.add(
                CookieHelper.buildCookieString(
                        CookieHelper.SESSION_COOKIE_NAME,
                        sessionId + "." + clientSessionId,
                        configurationService.getSessionCookieMaxAge(),
                        configurationService.getSessionCookieAttributes(),
                        configurationService.getDomainName()));
        cookies.add(
                CookieHelper.buildCookieString(
                        CookieHelper.PERSISTENT_COOKIE_NAME,
                        persistentSessionId,
                        configurationService.getPersistentCookieMaxAge(),
                        configurationService.getSessionCookieAttributes(),
                        configurationService.getDomainName()));

        String browserSessionId = orchSessionItem.getBrowserSessionId();

        if (browserSessionId != null) {
            cookies.add(
                    CookieHelper.buildCookieString(
                            CookieHelper.BROWSER_SESSION_COOKIE_NAME,
                            browserSessionId,
                            configurationService.getSessionCookieAttributes(),
                            configurationService.getOidcDomainName()));
        }

        getPrimaryLanguageFromUILocales(authRequest, configurationService)
                .ifPresent(
                        primaryLanguage -> {
                            LOG.info("Setting primary language: {}", primaryLanguage.getLanguage());
                            cookies.add(
                                    CookieHelper.buildCookieString(
                                            CookieHelper.LANGUAGE_COOKIE_NAME,
                                            primaryLanguage.getLanguage(),
                                            configurationService.getLanguageCookieMaxAge(),
                                            configurationService.getSessionCookieAttributes(),
                                            configurationService.getDomainName()));
                        });

        return cookies;
    }

    private AuthenticationRequest stripOutReauthenticateQueryParams(
            AuthenticationRequest authRequest) {
        return new AuthenticationRequest.Builder(authRequest)
                .customParameter("id_token_hint")
                .build();
    }

    private AuthenticationRequest stripOutLoginHintQueryParams(AuthenticationRequest authRequest) {
        return new AuthenticationRequest.Builder(authRequest).loginHint(null).build();
    }

    private SignedJWT getReauthIdToken(AuthenticationRequest authenticationRequest) {
        boolean isTokenSignatureValid =
                segmentedFunctionCall(
                        "isTokenSignatureValid",
                        () ->
                                tokenValidationService.isTokenSignatureValid(
                                        authenticationRequest
                                                .getCustomParameter("id_token_hint")
                                                .get(0)));
        if (!isTokenSignatureValid) {
            LOG.warn("Unable to validate ID token signature");
            throw new RuntimeException("Unable to validate id_token_hint");
        }

        SignedJWT idToken;
        String aud;
        try {
            idToken =
                    SignedJWT.parse(
                            authenticationRequest.getCustomParameter("id_token_hint").get(0));
            aud = idToken.getJWTClaimsSet().getAudience().stream().findFirst().orElse(null);
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse id_token_hint into SignedJWT");
            throw new RuntimeException("Invalid id_token_hint");
        }

        if (aud == null || !aud.equals(authenticationRequest.getClientID().getValue())) {
            LOG.warn("Audience on id_token_hint does not match client ID");
            throw new RuntimeException("Invalid id_token_hint for client");
        }
        return idToken;
    }
}
