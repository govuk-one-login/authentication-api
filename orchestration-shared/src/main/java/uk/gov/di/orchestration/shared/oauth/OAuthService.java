package uk.gov.di.orchestration.shared.oauth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OAuthConfiguration;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;

import static java.lang.String.format;
import static java.util.Collections.singletonList;

public class OAuthService {
    private static final long PRIVATE_KEY_JWT_EXPIRY = 5L;

    interface ResponseParser<T> {
        T parse(HTTPResponse response) throws ParseException;
    }

    protected final OAuthConfiguration clientConfig;
    private final OrchJwtService jwtService;
    private final NowHelper.NowClock clock;
    private final HTTPRequestSender httpRequestSender;
    private final StateStorageService stateStorageService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final Logger LOG = LogManager.getLogger(this.getClass());

    public OAuthService(
            OAuthConfiguration clientConfig,
            OrchJwtService jwtService,
            NowHelper.NowClock clock,
            StateStorageService stateStorageService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService) {
        this.clientConfig = clientConfig;
        this.jwtService = jwtService;
        this.clock = clock;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.httpRequestSender = null;
        this.stateStorageService = stateStorageService;
    }

    public OAuthService(
            OAuthConfiguration clientConfig,
            OrchJwtService jwtService,
            NowHelper.NowClock clock,
            HTTPRequestSender httpRequestSender,
            StateStorageService stateStorageService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService) {
        this.clientConfig = clientConfig;
        this.jwtService = jwtService;
        this.clock = clock;
        this.httpRequestSender = httpRequestSender;
        this.stateStorageService = stateStorageService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
    }

    public TokenResponse getToken(String authCode) {
        int count = 0;
        int maxTries = 2;
        TokenResponse tokenResponse;
        do {
            if (count > 0) LOG.warn("Retrying token request");
            count++;
            // We must generate a new token request every time:
            // private_key_jwt client auth JWTs are not reusable
            var tokenRequest = createTokenRequest(authCode);
            LOG.info("Sending Token request");
            tokenResponse = sendHttpRequest(tokenRequest.toHTTPRequest(), TokenResponse::parse);
            if (!tokenResponse.indicatesSuccess()) {
                HTTPResponse response = tokenResponse.toHTTPResponse();
                LOG.warn(
                        "Unsuccessful {} response from token endpoint: {} on attempt {}: {} ",
                        response.getStatusCode(),
                        tokenRequest.getEndpointURI().toString(),
                        count,
                        response.getBody());
            }
        } while (!tokenResponse.indicatesSuccess() && count < maxTries);

        return tokenResponse;
    }

    private TokenRequest createTokenRequest(String authCode) {
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode), clientConfig.redirectURI());
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(clientConfig.clientId()),
                        singletonList(new Audience(clientConfig.privateKeyJwtAudience())),
                        clock.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        clock.now(),
                        clock.now(),
                        new JWTID());
        var signedJWT =
                jwtService.signJWT(claimsSet.toJWTClaimsSet(), clientConfig.signingKeyAlias());
        return new TokenRequest.Builder(
                        clientConfig.tokenURI(), new PrivateKeyJWT(signedJWT), codeGrant)
                .customParameter("client_id", clientConfig.clientId())
                .build();
    }

    private <T> T sendHttpRequest(HTTPRequest httpRequest, ResponseParser<T> parser) {
        try {
            HTTPResponse response;
            if (httpRequestSender != null) {
                response = httpRequest.send(httpRequestSender);
            } else {
                // Currently we only use the above for dependency injection, but in future we should
                // create a custom HTTP client and remove this block!
                response = httpRequest.send();
            }

            return parser.parse(response);
        } catch (IOException e) {
            LOG.error("Error whilst sending request", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing response", e);
            throw new RuntimeException(e);
        }
    }

    public UserInfo getUserInfo(TokenResponse tokenResponse)
            throws UnsuccessfulCredentialResponseException {
        LOG.info("Sending userinfo request");
        var userInfoRequest =
                new UserInfoRequest(
                        clientConfig.userInfoURI(),
                        tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken());
        int count = 0;
        int maxTries = 2;
        UserInfoResponse userInfoResponse;
        do {
            if (count > 0) LOG.warn("Retrying user info request");
            count++;
            userInfoResponse =
                    sendHttpRequest(userInfoRequest.toHTTPRequest(), UserInfoResponse::parse);
            if (!userInfoResponse.indicatesSuccess()) {
                LOG.warn(
                        format(
                                "Unsuccessful %s response from userinfo endpoint on attempt %d: %s ",
                                userInfoResponse.toHTTPResponse().getStatusCode(),
                                count,
                                userInfoResponse.toHTTPResponse().getBody()));
            }
        } while (!userInfoResponse.indicatesSuccess() && count < maxTries);

        if (!userInfoResponse.indicatesSuccess()) {
            LOG.error("Response from userinfo endpoint does not indicate success");
            throw new UnsuccessfulCredentialResponseException(
                    userInfoResponse.toErrorResponse().toString());
        }
        return userInfoResponse.toSuccessResponse().getUserInfo();
    }

    public AuthorizationRequest createAuthorisationRequest(
            JWTClaimsSet claims, RSAPublicKey publicEncKey) {
        var encryptedJar =
                jwtService.signAndEncryptJWT(claims, clientConfig.signingKeyAlias(), publicEncKey);
        return new AuthorizationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new ClientID(clientConfig.clientId()))
                .endpointURI(clientConfig.authorizationURI())
                .requestObject(encryptedJar)
                .build();
    }

    public boolean isStateValid(String prefix, String sessionId, String responseState) {
        var valueFromDynamo =
                stateStorageService.getState(prefix + sessionId).map(StateItem::getState);
        if (valueFromDynamo.isEmpty()) {
            LOG.info("No state found in Dynamo");
            return false;
        }

        State storedState = new State(valueFromDynamo.get());
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }

    public void storeState(String prefix, State state, String sessionId, String clientSessionId) {
        stateStorageService.storeState(prefix + sessionId, state.getValue());
        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);
    }
}
