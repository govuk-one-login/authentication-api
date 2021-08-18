package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.AuthCodeExchangeData;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.TokenGeneratorService;
import uk.gov.di.services.TokenService;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.helpers.RequestBodyHelper.parseRequestBody;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(TokenHandler.class);

    private final ClientService clientService;
    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;
    private final AuthorisationCodeService authorisationCodeService;
    private final ClientSessionService clientSessionService;
    private static final String TOKEN_PATH = "/token";

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
                        configurationService,
                        new RedisConnectionService(configurationService),
                        new TokenGeneratorService(configurationService));
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
        Optional<ErrorObject> invalidRequestParamError =
                tokenService.validateTokenRequestParams(input.getBody());
        if (invalidRequestParamError.isPresent()) {
            LOG.error("Parameters missing from Token Request");
            return generateApiGatewayProxyResponse(
                    400, invalidRequestParamError.get().toJSONObject().toJSONString());
        }

        Map<String, String> requestBody = parseRequestBody(input.getBody());
        String clientID = requestBody.get("client_id");
        ClientRegistry client;
        try {
            client = clientService.getClient(clientID).orElseThrow();
        } catch (NoSuchElementException e) {
            LOG.error("Client not found in Client Registry with Client ID {}", clientID);
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString());
        }
        String baseUrl = configurationService.getBaseURL().orElseThrow();
        String tokenUrl = baseUrl + TOKEN_PATH;
        Optional<ErrorObject> invalidPrivateKeyJwtError =
                tokenService.validatePrivateKeyJWT(
                        input.getBody(), client.getPublicKey(), tokenUrl);
        if (invalidPrivateKeyJwtError.isPresent()) {
            LOG.error("Private Key JWT is not valid for Client ID {}", clientID);
            return generateApiGatewayProxyResponse(
                    400, invalidPrivateKeyJwtError.get().toJSONObject().toJSONString());
        }

        AuthCodeExchangeData authCodeExchangeData;
        try {
            authCodeExchangeData =
                    authorisationCodeService
                            .getExchangeDataForCode(requestBody.get("code"))
                            .orElseThrow();
        } catch (NoSuchElementException e) {
            LOG.error("Could not retrieve client session ID from code", e);
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        ClientSession clientSession =
                clientSessionService.getClientSession(authCodeExchangeData.getClientSessionId());
        AuthenticationRequest authRequest;
        try {
            authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        } catch (ParseException e) {
            LOG.error("Could not parse authentication request", e);
            throw new RuntimeException(
                    format(
                            "Unable to parse Auth Request\n Auth Request Params: %s \n Exception: %s",
                            clientSession.getAuthRequestParams(), e));
        }
        if (!authRequest.getRedirectionURI().toString().equals(requestBody.get("redirect_uri"))) {
            return generateApiGatewayProxyResponse(
                    400, OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString());
        }
        Subject subject =
                authenticationService.getSubjectFromEmail(authCodeExchangeData.getEmail());
        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        clientID, subject, authRequest.getScope().toStringList());

        clientSessionService.saveClientSession(
                authCodeExchangeData.getClientSessionId(),
                clientSession.setIdTokenHint(
                        tokenResponse.getOIDCTokens().getIDToken().serialize()));
        LOG.info("Successfully generated tokens");
        return generateApiGatewayProxyResponse(200, tokenResponse.toJSONObject().toJSONString());
    }
}
