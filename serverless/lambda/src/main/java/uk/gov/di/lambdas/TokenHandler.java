package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.di.entity.Client;
import uk.gov.di.services.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TokenHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    List<Client> clients = List.of(
            new Client(
                    "client-name",
                    "test-id",
                    "test-secret",
                    List.of("email"),
                    List.of("code"),
                    List.of("http://localhost:8080"),
                    List.of("contact@example.com")));

    private final ClientService clientService;
    private final AuthorizationCodeService authorizationCodeService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;

    public TokenHandler(ClientService clientService, AuthorizationCodeService authorizationCodeService, TokenService tokenService, AuthenticationService authenticationService) {
        this.clientService = clientService;
        this.authorizationCodeService = authorizationCodeService;
        this.tokenService = tokenService;
        this.authenticationService = authenticationService;
    }

    public TokenHandler() {
        clientService = new ClientService(clients, new AuthorizationCodeService());
        authorizationCodeService = new AuthorizationCodeService();
        tokenService = new TokenService();
        authenticationService = new UserService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
        LambdaLogger logger = context.getLogger();
        Map<String, String> requestBody = parseRequestBody(input.getBody());

        if (!requestBody.containsKey("code") || !requestBody.containsKey("client_id") || !requestBody.containsKey("client_secret")) {
            apiGatewayProxyResponseEvent.setStatusCode(400);
            apiGatewayProxyResponseEvent.setBody("Request is missing parameters");
            return apiGatewayProxyResponseEvent;
        }

        AuthorizationCode code = new AuthorizationCode(requestBody.get("code"));
        String clientSecret = requestBody.get("client_secret");
        String clientID = requestBody.get("client_id");

        if (!clientService.isValidClient(clientID, clientSecret)) {
            apiGatewayProxyResponseEvent.setStatusCode(403);
            apiGatewayProxyResponseEvent.setBody("client is not valid");
            return apiGatewayProxyResponseEvent;
        }
//        String email = authorizationCodeService.getEmailForCode(code);
        String email = "joe.bloggs@digital.cabinet-office.gov.uk";

        if (email.isEmpty()) {
            apiGatewayProxyResponseEvent.setStatusCode(403);
            apiGatewayProxyResponseEvent.setBody("");
            return apiGatewayProxyResponseEvent;
        }

        AccessToken accessToken = tokenService.issueToken(email);
        UserInfo userInfo = authenticationService.getInfoForEmail(email);
        SignedJWT idToken = tokenService.generateIDToken(clientID, userInfo.getSubject());

        OIDCTokens oidcTokens = new OIDCTokens(idToken, accessToken, null);
        OIDCTokenResponse tokenResponse = new OIDCTokenResponse(oidcTokens);

        apiGatewayProxyResponseEvent.setStatusCode(200);
        apiGatewayProxyResponseEvent.setBody(tokenResponse.toJSONObject().toJSONString());

        return apiGatewayProxyResponseEvent;
    }

    private Map<String, String> parseRequestBody(String body) {
        Map<String, String> query_pairs = new HashMap<>();
        String[] splitString = body.split("&");
        for (String pair : splitString) {
            int index = pair.indexOf("=");
            query_pairs.put(pair.substring(0, index), pair.substring(index + 1));
        }
        return query_pairs;
    }
}
