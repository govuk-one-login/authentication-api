package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.CookieHelper.SessionCookieIds;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.GA;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;
import static uk.gov.di.authentication.shared.state.StateMachine.userJourneyStateMachine;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger(AuthCodeHandler.class);

    public static final String COOKIE_CONSENT_ACCEPT = "accept";
    public static final String COOKIE_CONSENT_REJECT = "reject";
    public static final String COOKIE_CONSENT_NOT_ENGAGED = "not-engaged";

    private final SessionService sessionService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ConfigurationService configurationService;
    private final AuthorizationService authorizationService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            userJourneyStateMachine();

    public AuthCodeHandler(
            SessionService sessionService,
            AuthorisationCodeService authorisationCodeService,
            ConfigurationService configurationService,
            AuthorizationService authorizationService,
            ClientSessionService clientSessionService,
            AuditService auditService) {
        this.sessionService = sessionService;
        this.authorisationCodeService = authorisationCodeService;
        this.configurationService = configurationService;
        this.authorizationService = authorizationService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
    }

    public AuthCodeHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        sessionService = new SessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        authorizationService = new AuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
        auditService = new AuditService();
    }

    public AuthCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            SessionCookieIds sessionCookieIds;
                            Session session;
                            try {
                                sessionCookieIds =
                                        CookieHelper.parseSessionCookie(input.getHeaders())
                                                .orElseThrow();
                                session =
                                        sessionService
                                                .readSessionFromRedis(
                                                        sessionCookieIds.getSessionId())
                                                .orElseThrow();
                            } catch (NoSuchElementException e) {
                                LOGGER.error("SessionID not found");
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            }

                            attachSessionIdToLogs(session);

                            LOGGER.info(
                                    "AuthCodeHandler processing request for session: {}",
                                    session.getSessionId());

                            SessionState nextState;
                            try {
                                nextState =
                                        stateMachine.transition(
                                                session.getState(),
                                                SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE,
                                                UserContext.builder(session).build());
                            } catch (StateMachine.InvalidStateTransitionException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1017);
                            }

                            AuthenticationRequest authenticationRequest;
                            try {
                                Map<String, List<String>> authRequest =
                                        clientSessionService
                                                .getClientSession(
                                                        sessionCookieIds.getClientSessionId())
                                                .getAuthRequestParams();
                                authenticationRequest = AuthenticationRequest.parse(authRequest);
                            } catch (ParseException e) {
                                if (e.getRedirectionURI() == null) {
                                    LOGGER.error(
                                            "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request for session: {}",
                                            session.getSessionId(),
                                            e);
                                    // TODO - We need to come up with a strategy to handle uncaught
                                    // exceptions
                                    throw new RuntimeException(
                                            "Redirect URI or Client ID is missing from auth request",
                                            e);
                                }
                                AuthenticationErrorResponse errorResponse =
                                        authorizationService.generateAuthenticationErrorResponse(
                                                e.getRedirectionURI(),
                                                e.getState(),
                                                e.getResponseMode(),
                                                e.getErrorObject());
                                LOGGER.error(
                                        "Authentication request could not be parsed for session: {}. Generating error response",
                                        session.getSessionId(),
                                        e);
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        errorResponse.toURI().toString()));
                            }

                            try {
                                if (!authorizationService.isClientRedirectUriValid(
                                        authenticationRequest.getClientID(),
                                        authenticationRequest.getRedirectionURI())) {
                                    return generateInvalidClientRedirectError(
                                            session, authenticationRequest.getRedirectionURI());
                                }
                            } catch (ClientNotFoundException e) {
                                return generateClientNotFoundError(session, authenticationRequest);
                            }
                            VectorOfTrust requestedVectorOfTrust =
                                    clientSessionService
                                            .getClientSession(sessionCookieIds.getClientSessionId())
                                            .getEffectiveVectorOfTrust();
                            if (isNull(session.getCurrentCredentialStrength())
                                    || requestedVectorOfTrust
                                                    .getCredentialTrustLevel()
                                                    .compareTo(
                                                            session.getCurrentCredentialStrength())
                                            > 0) {
                                session.setCurrentCredentialStrength(
                                        requestedVectorOfTrust.getCredentialTrustLevel());
                            }
                            AuthorizationCode authCode =
                                    authorisationCodeService.generateAuthorisationCode(
                                            sessionCookieIds.getClientSessionId(),
                                            session.getEmailAddress());

                            try {
                                AuthenticationSuccessResponse authenticationResponse;

                                List<NameValuePair> additionalParams =
                                        getAdditionalQueryParams(
                                                input.getQueryStringParameters(),
                                                authenticationRequest);

                                authenticationResponse =
                                        authorizationService.generateSuccessfulAuthResponse(
                                                authenticationRequest, authCode, additionalParams);

                                sessionService.save(session.setState(nextState));
                                LOGGER.info(
                                        "AuthCodeHandler successfully processed request for session: {}",
                                        session.getSessionId());
                                auditService.submitAuditEvent(
                                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        authenticationRequest.getClientID().getValue(),
                                        AuditService.UNKNOWN,
                                        session.getEmailAddress(),
                                        IpAddressHelper.extractIpAddress(input),
                                        AuditService.UNKNOWN,
                                        PersistentIdHelper.extractPersistentIdFromCookieHeader(
                                                input.getHeaders()));
                                return new APIGatewayProxyResponseEvent()
                                        .withStatusCode(302)
                                        .withHeaders(
                                                Map.of(
                                                        ResponseHeaders.LOCATION,
                                                        authenticationResponse.toURI().toString()));
                            } catch (ClientNotFoundException e) {
                                return generateClientNotFoundError(session, authenticationRequest);
                            } catch (URISyntaxException e) {
                                return generateInvalidClientRedirectError(
                                        session, authenticationRequest.getRedirectionURI());
                            }
                        });
    }

    private List<NameValuePair> getAdditionalQueryParams(
            Map<String, String> queryParams, AuthenticationRequest authenticationRequest)
            throws ClientNotFoundException {
        List<NameValuePair> additionalParams = new ArrayList<>();

        if (authorizationService.isClientCookieConsentShared(authenticationRequest.getClientID())) {

            String cookieConsentValue = COOKIE_CONSENT_NOT_ENGAGED;

            if (isValidQueryParam(queryParams, COOKIE_CONSENT)) {
                cookieConsentValue = queryParams.get(COOKIE_CONSENT);
            }

            additionalParams.add(new BasicNameValuePair(COOKIE_CONSENT, cookieConsentValue));
        }

        if (isValidQueryParam(queryParams, GA)) {
            additionalParams.add(new BasicNameValuePair(GA, queryParams.get(GA)));
        }

        return additionalParams;
    }

    private boolean isValidQueryParam(Map<String, String> queryParams, String queryParam) {
        return queryParams != null
                && queryParams.containsKey(queryParam)
                && !queryParams.get(queryParam).isEmpty();
    }

    private APIGatewayProxyResponseEvent generateInvalidClientRedirectError(
            Session session, URI redirectURI) {
        LOGGER.error(
                "Invalid client redirect URI ({}) for session: {}",
                redirectURI,
                session.getSessionId());
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1016);
    }

    private APIGatewayProxyResponseEvent generateClientNotFoundError(
            Session session, AuthenticationRequest authenticationRequest) {
        AuthenticationErrorResponse errorResponse =
                authorizationService.generateAuthenticationErrorResponse(
                        authenticationRequest, OAuth2Error.INVALID_CLIENT);
        LOGGER.error(
                "Client not found for session: {}. Generating error response",
                session.getSessionId());
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of(ResponseHeaders.LOCATION, errorResponse.toURI().toString()));
    }
}
