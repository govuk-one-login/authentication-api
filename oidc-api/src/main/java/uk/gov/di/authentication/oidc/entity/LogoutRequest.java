package uk.gov.di.authentication.oidc.entity;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.CookieHelper.SessionCookieIds;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;

public class LogoutRequest {
    private static final Logger LOG = LogManager.getLogger(LogoutRequest.class);
    private final Optional<String> internalCommonSubjectId;
    private final Optional<String> sessionId;
    private final Optional<Map<String, String>> queryStringParameters;
    private Optional<String> state = Optional.empty();
    private Optional<String> idTokenHint = Optional.empty();
    private boolean isTokenSignatureValid = false;
    private TxmaAuditUser auditUser;
    private Optional<ErrorObject> errorObject = Optional.empty();
    private Optional<String> clientId = Optional.empty();
    private Optional<String> rpPairwiseId = Optional.empty();
    Optional<URI> postLogoutRedirectUri = Optional.empty();
    private Optional<ClientRegistry> clientRegistry = Optional.empty();
    private Optional<DestroySessionsRequest> destroySessionsRequest = Optional.empty();
    private Optional<OrchSessionItem> orchSession = Optional.empty();

    public LogoutRequest(
            TokenValidationService tokenValidationService,
            DynamoClientService dynamoClientService,
            APIGatewayProxyRequestEvent input,
            OrchSessionService orchSessionService) {

        var sessionCookieIds = CookieHelper.parseSessionCookie(input.getHeaders());
        sessionId = sessionCookieIds.map(SessionCookieIds::getSessionId);
        var clientSessionIdFromCookie = sessionCookieIds.map(SessionCookieIds::getClientSessionId);
        orchSession = sessionId.flatMap(orchSessionService::getSession);

        internalCommonSubjectId = orchSession.map(OrchSessionItem::getInternalCommonSubjectId);

        auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(input))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(input.getHeaders()))
                        .withGovukSigninJourneyId(clientSessionIdFromCookie.orElse(null))
                        .withUserId(internalCommonSubjectId.orElse(null));

        if (sessionId.isPresent() && orchSession.isPresent()) {
            destroySessionsRequest =
                    orchSession.map(s -> new DestroySessionsRequest(sessionId.get(), s));
            auditUser = auditUser.withSessionId(sessionId.get());
        }

        queryStringParameters = Optional.ofNullable(input.getQueryStringParameters());
        if (queryStringParameters.isEmpty()) {
            LOG.info("No input parameters present in logout request");
            return;
        }

        state = Optional.ofNullable(queryStringParameters.get().get("state"));
        idTokenHint = Optional.ofNullable(queryStringParameters.get().get("id_token_hint"));
        if (idTokenHint.isEmpty()) {
            LOG.info("No ID token hint present in logout request");
            return;
        }

        LOG.info("ID token hint is present");
        isTokenSignatureValid =
                segmentedFunctionCall(
                        "isTokenSignatureValid",
                        () -> tokenValidationService.isTokenSignatureValid(idTokenHint.get()));
        if (!isTokenSignatureValid) {
            LOG.warn("Unable to validate ID token signature");
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "unable to validate id_token_hint"));
            return;
        }

        try {
            SignedJWT idToken = SignedJWT.parse(idTokenHint.get());
            clientId = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
            rpPairwiseId = Optional.ofNullable(idToken.getJWTClaimsSet().getSubject());
            var clientSessionId = idToken.getJWTClaimsSet().getStringClaim("sid");
            auditUser =
                    Objects.nonNull(clientSessionId)
                            ? auditUser.withGovukSigninJourneyId(clientSessionId)
                            : auditUser;
        } catch (ParseException e) {
            LOG.warn("Unable to extract JWTClaimsSet to get the audience");
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE, "invalid id_token_hint"));
            return;
        }

        if (clientId.isEmpty() || rpPairwiseId.isEmpty()) {
            return;
        }

        LOG.info("Validating client ID");
        attachLogFieldToLogs(CLIENT_ID, clientId.get());
        clientRegistry = dynamoClientService.getClient(clientId.get());
        if (clientRegistry.isEmpty()) {
            LOG.warn("Client not found in client registry");
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"));
            return;
        }

        var postLogoutRedirectUriString =
                Optional.ofNullable(queryStringParameters.get().get("post_logout_redirect_uri"));

        if (postLogoutRedirectUriString.isEmpty()) {
            LOG.info("Post logout redirect URI not present in logout request");
            return;
        }

        if (!postLogoutRedirectUriInClientReg(postLogoutRedirectUriString.get())) {
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"));
            return;
        }

        try {
            postLogoutRedirectUri = Optional.of(URI.create(postLogoutRedirectUriString.get()));
        } catch (IllegalArgumentException e) {
            LOG.warn("Invalid post logout redirect URI: {}", postLogoutRedirectUriString.get());
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "invalid post logout redirect URI"));
        }
    }

    private boolean postLogoutRedirectUriInClientReg(String uri) {
        if (!clientRegistry.get().getPostLogoutRedirectUrls().contains(uri)) {
            LOG.warn(
                    "Client registry does not contain the post logout redirect URI which was sent in the logout request. Value is {}",
                    uri);
            return false;
        } else {
            LOG.info(
                    "Post logout redirect URI is present in logout request and client registry. Value is {}",
                    uri);
            return true;
        }
    }

    public Optional<String> internalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public Optional<DestroySessionsRequest> destroySessionsRequest() {
        return destroySessionsRequest;
    }

    public Optional<String> sessionId() {
        return sessionId;
    }

    public Optional<Map<String, String>> queryStringParameters() {
        return queryStringParameters;
    }

    public Optional<String> state() {
        return state;
    }

    public Optional<String> idTokenHint() {
        return idTokenHint;
    }

    public boolean isTokenSignatureValid() {
        return isTokenSignatureValid;
    }

    public TxmaAuditUser auditUser() {
        return auditUser;
    }

    public Optional<ErrorObject> errorObject() {
        return errorObject;
    }

    public Optional<String> clientId() {
        return clientId;
    }

    public Optional<String> rpPairwiseId() {
        return rpPairwiseId;
    }

    public Optional<URI> postLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public Optional<ClientRegistry> clientRegistry() {
        return clientRegistry;
    }

    public Optional<OrchSessionItem> orchSession() {
        return orchSession;
    }
}
