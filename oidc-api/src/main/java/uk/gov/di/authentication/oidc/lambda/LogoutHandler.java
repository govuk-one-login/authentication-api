package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class LogoutHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(LogoutHandler.class);

    private final ConfigurationService configurationService;
    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;
    private final ClientSessionService clientSessionService;
    private final TokenValidationService tokenValidationService;
    private final DynamoService dynamoService;

    public LogoutHandler() {
        this.configurationService = new ConfigurationService();
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.clientSessionService = new ClientSessionService(configurationService);
        this.tokenValidationService =
                new TokenValidationService(
                        configurationService, new KmsConnectionService(configurationService));
        this.dynamoService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    public LogoutHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            TokenValidationService tokenValidationService,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.tokenValidationService = tokenValidationService;
        this.dynamoService = dynamoService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Logout request received");
                            Optional<String> state;
                            if (input.getQueryStringParameters() == null
                                    || input.getQueryStringParameters().isEmpty()) {
                                LOG.info("No query string parameters in request");
                                state = Optional.empty();
                            } else {
                                state =
                                        Optional.ofNullable(
                                                input.getQueryStringParameters().get("state"));
                            }
                            Optional<Session> sessionFromSessionCookie =
                                    sessionService.getSessionFromSessionCookie(input.getHeaders());
                            return sessionFromSessionCookie
                                    .map(t -> processLogoutRequest(t, input, state))
                                    .orElse(generateDefaultLogoutResponse(state));
                        });
    }

    private APIGatewayProxyResponseEvent processLogoutRequest(
            Session session, APIGatewayProxyRequestEvent input, Optional<String> state) {
        LOG.info("LogoutHandler processing request for session {}", session.getSessionId());

        CookieHelper.SessionCookieIds sessionCookieIds =
                CookieHelper.parseSessionCookie(input.getHeaders()).get();

        Map<String, String> queryStringParameters = input.getQueryStringParameters();

        if (!session.getClientSessions().contains(sessionCookieIds.getClientSessionId())) {
            LOG.error("Client Session ID does not exist in Session: {}", session.getSessionId());
            return generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid Session"));
        }
        if (queryStringParameters.get("id_token_hint") == null
                || !queryStringParameters.containsKey("id_token_hint")
                || queryStringParameters.get("id_token_hint").isBlank()) {
            LOG.info("Deleting session from redis as no id token is present in request");
            sessionService.deleteSessionFromRedis(session.getSessionId());
            return generateDefaultLogoutResponse(state);
        }
        if (!doesIDTokenExistInSession(queryStringParameters.get("id_token_hint"), session)) {
            LOG.error("ID token does not exist in session {}", session.getSessionId());
            return generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "ID token does not exist in session"));
        }
        if (!tokenValidationService.isTokenSignatureValid(
                queryStringParameters.get("id_token_hint"))) {
            LOG.error(
                    "Unable to validate ID token signature for Session: {}",
                    session.getSessionId());
            return generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Unable to validate ID token signature"));
        }
        try {
            String idTokenHint = queryStringParameters.get("id_token_hint");
            SignedJWT idToken = SignedJWT.parse(idTokenHint);
            if (!doesSubjectExistInUserProfile(idToken.getJWTClaimsSet().getSubject(), session)) {
                return generateErrorLogoutResponse(
                        Optional.empty(),
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Invalid Subject in ID Token"));
            }
            Optional<String> audience =
                    idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            sessionService.deleteSessionFromRedis(session.getSessionId());
            return audience.map(
                            a ->
                                    validateClientIDAgainstClientRegistry(
                                            queryStringParameters, a, state))
                    .orElse(generateDefaultLogoutResponse(state));
        } catch (ParseException e) {
            LOG.error("Unable to parse id_token_hint into SignedJWT", e);
            return generateErrorLogoutResponse(
                    Optional.empty(),
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid id_token_hint"));
        }
    }

    private boolean doesSubjectExistInUserProfile(String subject, Session session) {
        UserProfile userProfile = dynamoService.getUserProfileByEmail(session.getEmailAddress());
        if (userProfile == null) {
            LOG.error("UserProfile not found using Email address in session");
            return false;
        }
        if (!userProfile.getPublicSubjectID().equals(subject)) {
            LOG.error("SubjectID in id token hint does not match PublicSubjectId in UserProfile");
            return false;
        }
        return true;
    }

    private boolean doesIDTokenExistInSession(String idTokenHint, Session session) {
        return session.getClientSessions().stream()
                .map(clientSessionService::getClientSession)
                .filter(Objects::nonNull)
                .anyMatch(cs -> idTokenHint.equals(cs.getIdTokenHint()));
    }

    private APIGatewayProxyResponseEvent validateClientIDAgainstClientRegistry(
            Map<String, String> queryStringParameters, String clientID, Optional<String> state) {
        Optional<ClientRegistry> clientRegistry = dynamoClientService.getClient(clientID);
        if (clientRegistry.isEmpty()) {
            LOG.error("Client not found in ClientRegistry for ClientID: {}", clientID);
            return generateErrorLogoutResponse(
                    state,
                    new ErrorObject(
                            OAuth2Error.UNAUTHORIZED_CLIENT_CODE,
                            "Client not found in ClientRegistry"));
        }

        if ((queryStringParameters.containsKey("post_logout_redirect_uri"))) {
            if (!clientRegistry
                    .get()
                    .getPostLogoutRedirectUrls()
                    .contains(queryStringParameters.get("post_logout_redirect_uri"))) {
                LOG.error(
                        "Client registry does not contain PostLogoutRedirectUri which was sent in the logout request. Value is {}",
                        queryStringParameters.get("post_logout_redirect_uri"));
                return generateErrorLogoutResponse(
                        state,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Client registry does not contain PostLogoutRedirectUri"));
            } else {
                LOG.info(
                        "The post_logout_redirect_uri is present in logout request and client registry. Value is {}",
                        queryStringParameters.get("post_logout_redirect_uri"));
                return generateLogoutResponseWithCustomLogoutUri(
                        URI.create(queryStringParameters.get("post_logout_redirect_uri")), state);
            }
        }
        LOG.info(
                "post_logout_redirect_uri is NOT present in logout request. Generating default logout response");
        return generateDefaultLogoutResponse(state);
    }

    private APIGatewayProxyResponseEvent generateDefaultLogoutResponse(Optional<String> state) {
        LOG.info("Generating default Logout Response");
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(), state, Optional.empty());
    }

    private APIGatewayProxyResponseEvent generateErrorLogoutResponse(
            Optional<String> state, ErrorObject errorObject) {
        LOG.info(
                "Generating Logout Error Response with code: {} and description: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(), state, Optional.of(errorObject));
    }

    private APIGatewayProxyResponseEvent generateLogoutResponseWithCustomLogoutUri(
            URI logoutUri, Optional<String> state) {
        return generateLogoutResponse(logoutUri, state, Optional.empty());
    }

    private APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri, Optional<String> state, Optional<ErrorObject> errorObject) {
        LOG.info("Generating Logout Response using URI: {}", logoutUri);
        URIBuilder uriBuilder = new URIBuilder(logoutUri);
        state.ifPresent(s -> uriBuilder.addParameter("state", s));
        errorObject.ifPresent(e -> uriBuilder.addParameter("error_code", e.getCode()));
        errorObject.ifPresent(
                e -> uriBuilder.addParameter("error_description", e.getDescription()));
        URI uri;
        try {
            uri = uriBuilder.build();
        } catch (URISyntaxException e) {
            LOG.error("Unable to generate logout response", e);
            throw new RuntimeException("Unable to build URI");
        }
        return new APIGatewayProxyResponseEvent()
                .withStatusCode(302)
                .withHeaders(Map.of(ResponseHeaders.LOCATION, uri.toString()));
    }
}
