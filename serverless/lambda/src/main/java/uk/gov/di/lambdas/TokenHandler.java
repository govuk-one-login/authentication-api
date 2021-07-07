package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.TokenService;

import java.util.Map;

import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.RequestBodyHelper.PARSE_REQUEST_BODY;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ClientService clientService;
    private final AuthorizationCodeService authorizationCodeService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;

    public TokenHandler(
            ClientService clientService,
            AuthorizationCodeService authorizationCodeService,
            TokenService tokenService,
            AuthenticationService authenticationService,
            ConfigurationService configurationService) {
        this.clientService = clientService;
        this.authorizationCodeService = authorizationCodeService;
        this.tokenService = tokenService;
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
    }

    public TokenHandler() {
        configurationService = new ConfigurationService();
        clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
        authorizationCodeService = new AuthorizationCodeService();
        tokenService = new TokenService(configurationService);
        this.authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();
        Map<String, String> requestBody = PARSE_REQUEST_BODY(input.getBody());

        if (!requestBody.containsKey("code") || !requestBody.containsKey("client_id")) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }

        AuthorizationCode code = new AuthorizationCode(requestBody.get("code"));
        String clientID = requestBody.get("client_id");

        if (!clientService.isValidClient(clientID)) {
            return generateApiGatewayProxyResponse(403, "client is not valid");
        }
        //        String email = authorizationCodeService.getEmailForCode(code);
        String email = "joe.bloggs@digital.cabinet-office.gov.uk";

        if (email.isEmpty()) {
            return generateApiGatewayProxyResponse(403, "");
        }

        AccessToken accessToken = tokenService.issueToken(email);
        Subject subject = authenticationService.getSubjectFromEmail(email);
        SignedJWT idToken = tokenService.generateIDToken(clientID, subject);

        OIDCTokens oidcTokens = new OIDCTokens(idToken, accessToken, null);
        OIDCTokenResponse tokenResponse = new OIDCTokenResponse(oidcTokens);

        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }
}
