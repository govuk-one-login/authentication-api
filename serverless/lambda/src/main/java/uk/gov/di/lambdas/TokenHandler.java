package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.TokenService;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.RequestBodyHelper.parseRequestBody;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientSessionService clientSessionService;

    public TokenHandler(
            ClientService clientService,
            TokenService tokenService,
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            AuthorisationCodeService authorisationCodeService,
            ClientSessionService clientSessionService) {
        this.clientService = clientService;
        this.tokenService = tokenService;
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.clientSessionService = clientSessionService;
    }

    public TokenHandler() {
        configurationService = new ConfigurationService();
        clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        tokenService =
                new TokenService(
                        configurationService, new RedisConnectionService(configurationService));
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        this.authorisationCodeService = new AuthorisationCodeService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        PrivateKeyJWT privateKeyJWT;
        Map<String, String> requestBody;
        try {
            requestBody = parseRequestParameters(input.getBody());
            privateKeyJWT = PrivateKeyJWT.parse(input.getBody());
        } catch (ParseException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        String clientID = requestBody.get("client_id");
        Optional<ClientRegistry> client = clientService.getClient(clientID);
        if (client.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(403, ErrorResponse.ERROR_1016);
        }

        boolean privateKeyJWTIsValid =
                tokenService.validatePrivateKeyJWTSignature(
                        client.get().getPublicKey(),
                        privateKeyJWT,
                        configurationService.getBaseURL().orElseThrow());
        if (!privateKeyJWTIsValid) {
            return generateApiGatewayProxyErrorResponse(403, ErrorResponse.ERROR_1015);
        }
        String clientSessionId;
        try {
            clientSessionId =
                    authorisationCodeService
                            .getClientSessionIdForCode(requestBody.get("code"))
                            .orElseThrow();
        } catch (NoSuchElementException e) {
            return generateApiGatewayProxyErrorResponse(403, ErrorResponse.ERROR_1018);
        }
        ClientSession clientSession = clientSessionService.getClientSession(clientSessionId);
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        } catch (ParseException e) {
            throw new RuntimeException(
                    format(
                            "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                            clientSession.getAuthRequestParams(), e));
        }
        Subject subject = authenticationService.getSubjectFromEmail(clientSession.getEmail());

        AccessToken accessToken =
                tokenService.generateAndStoreAccessToken(
                        clientID, subject, authRequest.getScope().toStringList());
        SignedJWT idToken = tokenService.generateIDToken(clientID, subject);
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null));
        clientSessionService.saveClientSession(
                clientSessionId, clientSession.setIdTokenHint(idToken.serialize()));
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }

    private Map<String, String> parseRequestParameters(String requestString) throws ParseException {
        Map<String, String> requestBody = parseRequestBody(requestString);
        if (!requestBody.containsKey("code")
                || !requestBody.containsKey("client_id")
                || !requestBody.containsKey("grant_type")
                || !requestBody.containsKey("redirect_uri")) {
            throw new ParseException("Request is missing parameters");
        }
        return requestBody;
    }
}
