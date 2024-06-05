package uk.gov.di.authentication.oidc.entity;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;

public class ParsedLogoutRequest {
    private static final Logger LOG = LogManager.getLogger(ParsedLogoutRequest.class);
    private Optional<Session> session = Optional.empty();
    private Optional<String> subjectId = Optional.empty();
    private Optional<String> sessionId = Optional.empty();
    private Optional<String> journeyId = Optional.empty();
    private Optional<Map<String, String>> queryStringParameters;
    private Optional<String> state = Optional.empty();
    private Optional<String> idTokenHint = Optional.empty();
    private boolean isTokenSignatureValid = false;
    private TxmaAuditUser auditUser;
    private Optional<ErrorObject> errorObject = Optional.empty();
    private Optional<String> clientId = Optional.empty();
    Optional<String> postLogoutRedirectUri = Optional.empty();
    private Optional<ClientRegistry> clientRegistry = Optional.empty();
    private final CookieHelper cookieHelper = new CookieHelper();

    private ParsedLogoutRequest() {}

    public ParsedLogoutRequest(
            SessionService sessionService,
            TokenValidationService tokenValidationService,
            DynamoClientService dynamoClientService,
            APIGatewayProxyRequestEvent input) {

        session =
                segmentedFunctionCall(
                        "getSessionFromSessionCookie",
                        () -> sessionService.getSessionFromSessionCookie(input.getHeaders()));

        subjectId = session.map(Session::getInternalCommonSubjectIdentifier);
        sessionId = session.map(Session::getSessionId);
        journeyId = extractClientSessionIdFromCookieHeaders(input.getHeaders());

        auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(input))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(input.getHeaders()))
                        .withSessionId(sessionId.orElse(null))
                        .withGovukSigninJourneyId(journeyId.orElse(null))
                        .withUserId(subjectId.orElse(null));

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

        if (clientId.isEmpty()) {
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

        postLogoutRedirectUri =
                Optional.ofNullable(queryStringParameters.get().get("post_logout_redirect_uri"));
        if (postLogoutRedirectUri.isEmpty()) {
            LOG.info("Post logout redirect URI not present in logout request");
            return;
        }

        if (!postLogoutRedirectUriInClientReg()) {
            errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"));
        }
    }

    private boolean postLogoutRedirectUriInClientReg() {
        return postLogoutRedirectUri
                .map(
                        uri -> {
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
                        })
                .orElse(false);
    }

    private Optional<String> extractClientSessionIdFromCookieHeaders(Map<String, String> headers) {
        var sessionCookieIds = cookieHelper.parseSessionCookie(headers);
        return sessionCookieIds.map(CookieHelper.SessionCookieIds::getClientSessionId);
    }

    public Optional<Session> session() {
        return session;
    }

    public Optional<String> subjectId() {
        return subjectId;
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

    public Optional<String> postLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public Optional<ClientRegistry> clientRegistry() {
        return clientRegistry;
    }
}
