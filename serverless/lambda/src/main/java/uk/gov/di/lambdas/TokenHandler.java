package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoClientService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.TokenService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
        Map<String, String> requestBody = PARSE_REQUEST_BODY(input.getBody());

        if (!requestBody.containsKey("code")
                || !requestBody.containsKey("client_id")
                || !requestBody.containsKey("grant_type")
                || !requestBody.containsKey("redirect_uri")) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        PrivateKeyJWT privateKeyJWT;
        try {
            privateKeyJWT = PrivateKeyJWT.parse(input.getBody());
        } catch (ParseException e) {
            return generateApiGatewayProxyResponse(400, "Invalid PrivateKeyJWT");
        }
        String clientID = privateKeyJWT.getClientID().toString();
        Optional<ClientRegistry> client = clientService.getClient(clientID);
        if (client.isEmpty()) {
            return generateApiGatewayProxyResponse(403, "client is not valid");
        }
        ClientAuthenticationVerifier<?> authenticationVerifier =
                new ClientAuthenticationVerifier<>(
                        generateClientCredentialsSelector(client.get()),
                        Collections.singleton(
                                new Audience(configurationService.getBaseURL().orElseThrow())));
        try {
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException | JOSEException e) {
            return generateApiGatewayProxyResponse(403, "Unable to Verify PrivateKeyJWT");
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

    private ClientCredentialsSelector<?> generateClientCredentialsSelector(
            ClientRegistry clientRegistry) {
        return new ClientCredentialsSelector<>() {
            @Override
            public List<Secret> selectClientSecrets(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {
                return null;
            }

            @Override
            public List<PublicKey> selectPublicKeys(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    JWSHeader jwsHeader,
                    boolean forceRefresh,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {

                String publicKey = clientRegistry.getPublicKey();
                byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
                try {
                    X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return Collections.singletonList(kf.generatePublic(x509publicKey));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
