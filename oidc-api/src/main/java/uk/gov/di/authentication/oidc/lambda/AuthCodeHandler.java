package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.services.AuthorizationService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.util.Map;
import java.util.Objects;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.shared.conditions.DocAppUserHelper.getRequestObjectClaim;
import static uk.gov.di.authentication.shared.conditions.DocAppUserHelper.isDocCheckingAppUserWithSubjectId;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class AuthCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(AuthCodeHandler.class);

    private final SessionService sessionService;
    private final AuthorisationCodeService authorisationCodeService;
    private final AuthorizationService authorizationService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;

    public AuthCodeHandler(
            SessionService sessionService,
            AuthorisationCodeService authorisationCodeService,
            AuthorizationService authorizationService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        this.sessionService = sessionService;
        this.authorisationCodeService = authorisationCodeService;
        this.authorizationService = authorizationService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
    }

    public AuthCodeHandler(ConfigurationService configurationService) {
        sessionService = new SessionService(configurationService);
        authorisationCodeService = new AuthorisationCodeService(configurationService);
        authorizationService = new AuthorizationService(configurationService);
        clientSessionService = new ClientSessionService(configurationService);
        auditService = new AuditService(configurationService);
        cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
        this.configurationService = configurationService;
    }

    public AuthCodeHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(),
                () -> authCodeRequestHandler(input, context));
    }

    public APIGatewayProxyResponseEvent authCodeRequestHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            Session session =
                                    sessionService
                                            .getSessionFromRequestHeaders(input.getHeaders())
                                            .orElse(null);
                            if (Objects.isNull(session)) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            }
                            String clientSessionId =
                                    getHeaderValueFromHeaders(
                                            input.getHeaders(),
                                            CLIENT_SESSION_ID_HEADER,
                                            configurationService.getHeadersCaseInsensitive());

                            if (Objects.isNull(clientSessionId)) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1018);
                            }
                            attachSessionIdToLogs(session);
                            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);

                            LOG.info("Processing request");

                            AuthenticationRequest authenticationRequest;
                            ClientSession clientSession;
                            try {
                                clientSession =
                                        clientSessionService
                                                .getClientSessionFromRequestHeaders(
                                                        input.getHeaders())
                                                .orElse(null);
                                if (Objects.isNull(clientSession)) {
                                    LOG.info("ClientSession not found");
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1018);
                                }
                                authenticationRequest =
                                        AuthenticationRequest.parse(
                                                clientSession.getAuthRequestParams());
                            } catch (ParseException e) {
                                if (e.getRedirectionURI() == null) {
                                    LOG.warn(
                                            "Authentication request could not be parsed: redirect URI or Client ID is missing from auth request",
                                            e);
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
                                LOG.warn("Authentication request could not be parsed", e);
                                return generateResponse(
                                        new AuthCodeResponse(errorResponse.toURI().toString()));
                            }
                            addAnnotation(
                                    "client_id",
                                    String.valueOf(
                                            clientSession.getAuthRequestParams().get("client_id")));

                            URI redirectUri = authenticationRequest.getRedirectionURI();
                            State state = authenticationRequest.getState();
                            try {
                                boolean docCheckingUser =
                                        isDocCheckingAppUserWithSubjectId(clientSession);
                                if (docCheckingUser) {
                                    redirectUri =
                                            URI.create(
                                                    getRequestObjectClaim(
                                                            authenticationRequest,
                                                            "redirect_uri",
                                                            String.class));
                                    state =
                                            new State(
                                                    getRequestObjectClaim(
                                                            authenticationRequest,
                                                            "state",
                                                            String.class));
                                }
                                if (!authorizationService.isClientRedirectUriValid(
                                        authenticationRequest.getClientID(), redirectUri)) {
                                    return generateApiGatewayProxyErrorResponse(
                                            400, ErrorResponse.ERROR_1016);
                                }
                                VectorOfTrust requestedVectorOfTrust =
                                        clientSession.getEffectiveVectorOfTrust();
                                if (isNull(session.getCurrentCredentialStrength())
                                        || requestedVectorOfTrust
                                                        .getCredentialTrustLevel()
                                                        .compareTo(
                                                                session
                                                                        .getCurrentCredentialStrength())
                                                > 0) {
                                    session.setCurrentCredentialStrength(
                                            requestedVectorOfTrust.getCredentialTrustLevel());
                                }
                                AuthorizationCode authCode =
                                        authorisationCodeService.generateAuthorisationCode(
                                                clientSessionId,
                                                session.getEmailAddress(),
                                                clientSession);

                                AuthenticationSuccessResponse authenticationResponse =
                                        authorizationService.generateSuccessfulAuthResponse(
                                                authenticationRequest,
                                                authCode,
                                                redirectUri,
                                                state);

                                LOG.info("Successfully processed request");

                                cloudwatchMetricsService.incrementCounter(
                                        "SignIn",
                                        Map.of(
                                                "Account",
                                                session.isNewAccount().name(),
                                                "Environment",
                                                configurationService.getEnvironment(),
                                                "Client",
                                                authenticationRequest.getClientID().getValue()));

                                if (!docCheckingUser) {
                                    LOG.info(
                                            "isDocCheckingAppUserWithSubjectId => authenticated = false");
                                }
                                sessionService.save(
                                        session.setAuthenticated(!docCheckingUser)
                                                .setNewAccount(EXISTING));

                                auditService.submitAuditEvent(
                                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                                        context.getAwsRequestId(),
                                        session.getSessionId(),
                                        authenticationRequest.getClientID().getValue(),
                                        AuditService.UNKNOWN,
                                        session.getEmailAddress(),
                                        IpAddressHelper.extractIpAddress(input),
                                        AuditService.UNKNOWN,
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));
                                return generateResponse(
                                        new AuthCodeResponse(
                                                authenticationResponse.toURI().toString()));
                            } catch (ClientNotFoundException e) {
                                AuthenticationErrorResponse errorResponse =
                                        authorizationService.generateAuthenticationErrorResponse(
                                                authenticationRequest,
                                                OAuth2Error.INVALID_CLIENT,
                                                redirectUri,
                                                state);
                                return generateResponse(
                                        new AuthCodeResponse(errorResponse.toURI().toString()));
                            }
                        });
    }

    private APIGatewayProxyResponseEvent generateResponse(AuthCodeResponse response) {
        try {
            return generateApiGatewayProxyResponse(200, response);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
