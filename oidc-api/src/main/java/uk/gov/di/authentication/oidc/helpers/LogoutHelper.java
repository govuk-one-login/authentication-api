package uk.gov.di.authentication.oidc.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;

public class LogoutHelper {
    private static final Logger LOG = LogManager.getLogger(LogoutHelper.class);
    private Optional<Session> session;
    private Optional<String> subjectId = Optional.empty();
    private Optional<String> sessionId = Optional.empty();
    private Optional<Map<String, String>> queryStringParameters;
    private Optional<String> state = Optional.empty();
    private Optional<String> idTokenHint = Optional.empty();
    private boolean isTokenSignatureValid = false;
    private TxmaAuditUser auditUser;
    private Optional<ErrorObject> errorObject = Optional.empty();
    private Optional<String> audience = Optional.empty();
    Optional<String> postLogoutRedirectUri = Optional.empty();
    private Optional<ClientRegistry> clientRegistry;
    SessionService sessionService;
    private TokenValidationService tokenValidationService;
    private DynamoClientService dynamoClientService;

    private LogoutHelper() {}

    public LogoutHelper(
            SessionService sessionService,
            TokenValidationService tokenValidationService,
            DynamoClientService dynamoClientService) {
        this.sessionService = sessionService;
        this.tokenValidationService = tokenValidationService;
        this.dynamoClientService = dynamoClientService;
    }

    public void extractParamsFromRequest(APIGatewayProxyRequestEvent input) throws ParseException {
        this.session =
                segmentedFunctionCall(
                        "getSessionFromSessionCookie",
                        () -> sessionService.getSessionFromSessionCookie(input.getHeaders()));
        Optional<String> subjectId = session.map(Session::getInternalCommonSubjectIdentifier);
        Optional<String> sessionId = session.map(Session::getSessionId);

        this.auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(input))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(input.getHeaders()))
                        .withSessionId(sessionId.orElse(null))
                        .withUserId(subjectId.orElse(null));

        this.queryStringParameters = Optional.ofNullable(input.getQueryStringParameters());
        if (this.queryStringParameters.isPresent()) {
            this.state = Optional.ofNullable(queryStringParameters.get().get("state"));
            this.idTokenHint =
                    Optional.ofNullable(queryStringParameters.get().get("id_token_hint"));
            this.postLogoutRedirectUri =
                    Optional.ofNullable(
                            queryStringParameters.get().get("post_logout_redirect_uri"));

            if (this.idTokenHint.isPresent()) {
                LOG.info("ID token hint is present");
                this.isTokenSignatureValid =
                        segmentedFunctionCall(
                                "isTokenSignatureValid",
                                () ->
                                        tokenValidationService.isTokenSignatureValid(
                                                idTokenHint.get()));
            }
            if (isTokenSignatureValid) {
                SignedJWT idToken = SignedJWT.parse(idTokenHint.get());
                this.audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();

                if (this.audience.isPresent()) {
                    this.clientRegistry = dynamoClientService.getClient(audience.get());
                }
            }
        }
    }

    public LogoutValidationResult validateRequest() {
        if (this.queryStringParameters.isEmpty()) {
            LOG.info("Returning default logout as no input parameters");
            return LogoutValidationResult.INCOMPLETE;
        }
        if (this.idTokenHint.isEmpty()) {
            LOG.info("Returning default logout as idTokenHint is empty");
            return LogoutValidationResult.INCOMPLETE;
        }
        if (!this.isTokenSignatureValid) {
            LOG.warn("Returning error logout as unable to validate ID token signature");
            this.errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "unable to validate id_token_hint"));
            return LogoutValidationResult.ERROR;
        }
        if (this.audience.isEmpty()) {
            return LogoutValidationResult.ERROR;
        }

        LOG.info("Validating ClientID");
        attachLogFieldToLogs(CLIENT_ID, this.audience.get());
        if (this.clientRegistry.isEmpty()) {
            LOG.warn("Client not found in ClientRegistry");
            this.errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE, "client not found"));
            return LogoutValidationResult.ERROR;
        }
        if (this.postLogoutRedirectUri.isEmpty()) {
            LOG.info(
                    "post_logout_redirect_uri is NOT present in logout request. Generating default logout response");
            return LogoutValidationResult.INCOMPLETE;
        }
        if (!postLogoutRedirectUriInClientReg()) {
            this.errorObject =
                    Optional.of(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "client registry does not contain post_logout_redirect_uri"));
            return LogoutValidationResult.ERROR;
        }

        return LogoutValidationResult.VALID;
    }

    private boolean postLogoutRedirectUriInClientReg() {
        return postLogoutRedirectUri
                .map(
                        uri -> {
                            if (!this.clientRegistry
                                    .get()
                                    .getPostLogoutRedirectUrls()
                                    .contains(uri)) {
                                LOG.warn(
                                        "Client registry does not contain PostLogoutRedirectUri which was sent in the logout request. Value is {}",
                                        uri);
                                return false;
                            } else {
                                LOG.info(
                                        "The post_logout_redirect_uri is present in logout request and client registry. Value is {}",
                                        uri);
                                return true;
                            }
                        })
                .orElseGet(() -> false);
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

    public Optional<String> state() {
        return state;
    }

    public TxmaAuditUser auditUser() {
        return auditUser;
    }

    public Optional<ErrorObject> errorObject() {
        return errorObject;
    }

    public Optional<String> audience() {
        return audience;
    }

    public Optional<String> postLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public enum LogoutValidationResult {
        VALID,
        INCOMPLETE,
        ERROR
    }
}
