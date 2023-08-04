package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.helpers.RequestObjectToAuthRequestHelper;
import uk.gov.di.authentication.oidc.services.AuthorizationService;
import uk.gov.di.authentication.oidc.services.RequestObjectService;
import uk.gov.di.authentication.shared.conditions.IdentityHelper;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LocaleHelper.getPrimaryLanguageFromUILocales;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedSessionIdToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuthorisationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthorisationHandler.class);

    private final SessionService sessionService;
    private final ConfigurationService configurationService;
    private final ClientSessionService clientSessionService;
    private final AuthorizationService authorizationService;
    private final RequestObjectService requestObjectService;
    private final AuditService auditService;
    private final ClientService clientService;

    public AuthorisationHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            AuthorizationService authorizationService,
            AuditService auditService,
            RequestObjectService requestObjectService,
            ClientService clientService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.clientSessionService = clientSessionService;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
        this.requestObjectService = requestObjectService;
        this.clientService = clientService;
    }

    public AuthorisationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.authorizationService = new AuthorizationService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.requestObjectService = new RequestObjectService(configurationService);
        this.clientService = new DynamoClientService(configurationService);
    }

    public AuthorisationHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> authoriseRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authoriseRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        var persistentSessionId =
                authorizationService.getExistingOrCreateNewPersistentSessionId(input.getHeaders());
        var ipAddress = IpAddressHelper.extractIpAddress(input);
        var clientSessionId = clientSessionService.generateClientSessionId();
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                clientSessionId,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                persistentSessionId);
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, persistentSessionId);
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Received authentication request");

        Map<String, List<String>> queryStringParameters;
        AuthenticationRequest authRequest;
        try {
            queryStringParameters =
                    input.getQueryStringParameters().entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey, entry -> List.of(entry.getValue())));
            authRequest = AuthenticationRequest.parse(queryStringParameters);
        } catch (ParseException e) {
            if (e.getRedirectionURI() == null) {
                LOG.warn(
                        "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request");
                throw new RuntimeException(
                        "Redirect URI or ClientID is missing from auth request", e);
            }
            LOG.warn("Authentication request could not be parsed", e);
            return generateErrorResponse(
                    e.getRedirectionURI(),
                    e.getState(),
                    e.getResponseMode(),
                    e.getErrorObject(),
                    ipAddress,
                    persistentSessionId,
                    AuditService.UNKNOWN,
                    clientSessionId);
        } catch (NullPointerException e) {
            LOG.warn("No query string parameters are present in the Authentication request", e);
            throw new RuntimeException(
                    "No query string parameters are present in the Authentication request", e);
        }
        Optional<AuthRequestError> authRequestError;
        if (authRequest.getRequestObject() != null && configurationService.isDocAppApiEnabled()) {
            LOG.info("RequestObject auth request received");
            authRequestError = requestObjectService.validateRequestObject(authRequest);
        } else {
            authRequestError =
                    authorizationService.validateAuthRequest(
                            authRequest, configurationService.isNonceRequired());
        }

        if (authRequestError.isPresent()) {
            return generateErrorResponse(
                    authRequestError.get().getRedirectURI(),
                    authRequest.getState(),
                    authRequest.getResponseMode(),
                    authRequestError.get().getErrorObject(),
                    ipAddress,
                    persistentSessionId,
                    authRequest.getClientID().getValue(),
                    clientSessionId);
        } else {
            authRequest = RequestObjectToAuthRequestHelper.transform(authRequest);
            return getOrCreateSessionAndRedirect(
                    sessionService.getSessionFromSessionCookie(input.getHeaders()),
                    authRequest,
                    ipAddress,
                    persistentSessionId,
                    clientSessionId);
        }
    }

    private APIGatewayProxyResponseEvent getOrCreateSessionAndRedirect(
            Optional<Session> existingSession,
            AuthenticationRequest authenticationRequest,
            String ipAddress,
            String persistentSessionId,
            String clientSessionId) {
        if (Objects.nonNull(authenticationRequest.getPrompt())
                && (authenticationRequest.getPrompt().contains(Prompt.Type.CONSENT)
                        || authenticationRequest
                                .getPrompt()
                                .contains(Prompt.Type.SELECT_ACCOUNT))) {
            return generateErrorResponse(
                    authenticationRequest.getRedirectionURI(),
                    authenticationRequest.getState(),
                    authenticationRequest.getResponseMode(),
                    OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
                    ipAddress,
                    persistentSessionId,
                    authenticationRequest.getClientID().getValue(),
                    clientSessionId);
        }
        var session = existingSession.orElseGet(sessionService::createSession);
        attachSessionIdToLogs(session);

        if (existingSession.isEmpty()) {
            updateAttachedSessionIdToLogs(session.getSessionId());
            LOG.info("Created session");
        } else {
            var oldSessionId = session.getSessionId();
            sessionService.updateSessionId(session);
            updateAttachedSessionIdToLogs(session.getSessionId());
            LOG.info("Updated session id from {} - new", oldSessionId);
        }

        ClientRegistry fullClientDetailsFromRegistry =
                clientService
                        .getClient(authenticationRequest.getClientID().getValue())
                        .orElseThrow(
                                () ->
                                        new RuntimeException(
                                                "Client not found: "
                                                        + authenticationRequest
                                                                .getClientID()
                                                                .getValue()));

        var clientName = fullClientDetailsFromRegistry.getClientName();

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_INITIATED,
                clientSessionId,
                session.getSessionId(),
                authenticationRequest.getClientID().getValue(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                persistentSessionId,
                pair("client-name", clientName));
        var clientSession =
                clientSessionService.generateClientSession(
                        authenticationRequest.toParameters(),
                        LocalDateTime.now(),
                        authorizationService.getEffectiveVectorOfTrust(authenticationRequest),
                        clientName);
        clientSessionService.storeClientSession(clientSessionId, clientSession);

        session.addClientSession(clientSessionId);
        updateAttachedLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        updateAttachedLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
        updateAttachedLogFieldToLogs(CLIENT_ID, authenticationRequest.getClientID().getValue());
        sessionService.save(session);
        LOG.info("Session saved successfully");
        return redirect(
                session,
                clientSessionId,
                authenticationRequest,
                persistentSessionId,
                fullClientDetailsFromRegistry);
    }

    private APIGatewayProxyResponseEvent redirect(
            Session session,
            String clientSessionID,
            AuthenticationRequest authenticationRequest,
            String persistentSessionId,
            ClientRegistry client) {
        LOG.info("Redirecting");
        String redirectURI;
        try {
            var redirectUriBuilder = new URIBuilder(configurationService.getLoginURI());

            if (configurationService.isAuthOrchSplitEnabled()) {
                redirectUriBuilder.setPath("authorize");
            }

            if (Objects.nonNull(authenticationRequest.getPrompt())
                    && authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)) {
                redirectUriBuilder.addParameter("prompt", String.valueOf(Prompt.Type.LOGIN));
            }
            redirectURI = redirectUriBuilder.build().toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Error constructing redirect URI", e);
        }
        List<String> cookies = new ArrayList<>();
        cookies.add(
                CookieHelper.buildCookieString(
                        CookieHelper.SESSION_COOKIE_NAME,
                        session.getSessionId() + "." + clientSessionID,
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

        getPrimaryLanguageFromUILocales(authenticationRequest, configurationService)
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

        if (configurationService.isAuthOrchSplitEnabled()) {
            var jwtID = IdGenerator.generate();
            var expiryDate = NowHelper.nowPlus(3, ChronoUnit.MINUTES);
            var claimsBuilder =
                    new JWTClaimsSet.Builder()
                            .issuer(configurationService.getOrchestrationClientId())
                            .audience(configurationService.getAuthAudience())
                            .expirationTime(expiryDate)
                            .issueTime(NowHelper.now())
                            .notBeforeTime(NowHelper.now())
                            .jwtID(jwtID)
                            .claim("client_name", client.getClientName())
                            .claim("cookie_consent_shared", client.isCookieConsentShared())
                            .claim("consent_required", client.isConsentRequired())
                            .claim("is_one_login_service", client.isOneLoginService())
                            .claim("service_type", client.getServiceType())
                            .claim("govuk_signin_journey_id", clientSessionID)
                            .claim(
                                    "confidence",
                                    authorizationService
                                            .getEffectiveVectorOfTrust(authenticationRequest)
                                            .getCredentialTrustLevel()
                                            .getValue())
                            .claim("state", new State())
                            .claim("client_id", configurationService.getOrchestrationClientId())
                            .claim(
                                    "scope",
                                    ValidScopes.extractAuthScopesFromRequestedScopes(
                                                    authenticationRequest.getScope())
                                            .toString())
                            .claim(
                                    "redirect_uri",
                                    configurationService.getOrchestrationRedirectUri());

            var claimsSetRequest =
                    constructAdditionalAuthenticationClaims(client, authenticationRequest);
            claimsSetRequest.ifPresent(t -> claimsBuilder.claim("claim", t.toJSONString()));
            var encryptedJWT = authorizationService.getSignedAndEncryptedJWT(claimsBuilder.build());

            var authorizationRequest =
                    new AuthorizationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    new ClientID(configurationService.getOrchestrationClientId()))
                            .endpointURI(URI.create(redirectURI))
                            .requestObject(encryptedJWT)
                            .build();

            redirectURI = authorizationRequest.toURI().toString();
        }

        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, redirectURI),
                Map.of(ResponseHeaders.SET_COOKIE, cookies));
    }

    private APIGatewayProxyResponseEvent generateErrorResponse(
            URI redirectUri,
            State state,
            ResponseMode responseMode,
            ErrorObject errorObject,
            String ipAddress,
            String persistentSessionId,
            String clientId,
            String clientSessionId) {

        auditService.submitAuditEvent(
                OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                clientSessionId,
                AuditService.UNKNOWN,
                clientId,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                ipAddress,
                AuditService.UNKNOWN,
                persistentSessionId,
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
                IdentityHelper.identityRequired(
                        authenticationRequest.toParameters(),
                        clientRegistry.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());

        var claimsSetRequest = new ClaimsSetRequest();
        if (identityRequired) {
            LOG.info("Identity is required. Adding the local_account_id and salt claims");
            claimsSetRequest = claimsSetRequest.add("local_account_id").add("salt");
        }
        if (authenticationRequest
                .getScope()
                .toStringList()
                .contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
            LOG.info("am scope is present. Adding the public_subject_id claim");
            claimsSetRequest = claimsSetRequest.add("public_subject_id");
        }
        if (authenticationRequest
                .getScope()
                .toStringList()
                .contains(CustomScopeValue.GOVUK_ACCOUNT.getValue())) {
            LOG.info("govuk-account scope is present. Adding the legacy_subject_id claim");
            claimsSetRequest = claimsSetRequest.add("legacy_subject_id");
        }

        if (claimsSetRequest.getEntries().isEmpty()) {
            LOG.info("No additional claims to add to request");
            return Optional.empty();
        }
        return Optional.of(new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest));
    }
}
