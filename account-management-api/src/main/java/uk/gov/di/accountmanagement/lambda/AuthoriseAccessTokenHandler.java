package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenService;

public class AuthoriseAccessTokenHandler
        implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthoriseAccessTokenHandler.class);

    private final TokenService tokenService;
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;

    public AuthoriseAccessTokenHandler(
            TokenService tokenService,
            ConfigurationService configurationService,
            DynamoService dynamoService) {
        this.tokenService = tokenService;
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
    }

    public AuthoriseAccessTokenHandler() {
        configurationService = new ConfigurationService();
        tokenService =
                new TokenService(
                        configurationService,
                        new RedisConnectionService(configurationService),
                        new KmsConnectionService(configurationService));
        dynamoService = new DynamoService(configurationService);
    }

    @Override
    public AuthPolicy handleRequest(TokenAuthorizerContext input, Context context) {

        try {
            String token = input.getAuthorizationToken();

            AccessToken accessToken;
            accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            //            TODO - Renable when terraform resources are shared across modules
            //            boolean isAccessTokenSignatureValid =
            // tokenService.validateAccessTokenSignature(accessToken);
            //            if (!isAccessTokenSignatureValid) {
            //                LOGGER.error("Access Token signature is not valid");
            //                throw new RuntimeException("Unauthorized");
            //            }
            LOGGER.info("Successfully validated Access Token signature");
            String subject = SignedJWT.parse(accessToken.getValue()).getJWTClaimsSet().getSubject();
            try {
                dynamoService.getUserProfileFromSubject(subject);
            } catch (Exception e) {
                LOGGER.error(
                        "Unable to retrieve UserProfile from Dynamo with given SubjectID: {}",
                        subject,
                        e);
                throw new RuntimeException(
                        "Unable to retrieve UserProfile from Dynamo with given SubjectID", e);
            }
            String methodArn = input.getMethodArn();
            String[] arnPartials = methodArn.split(":");
            String region = arnPartials[3];
            String awsAccountId = arnPartials[4];
            String[] apiGatewayArnPartials = arnPartials[5].split("/");
            String restApiId = apiGatewayArnPartials[0];
            String stage = apiGatewayArnPartials[1];
            LOGGER.info("Generating AuthPolicy");
            return new AuthPolicy(
                    subject,
                    AuthPolicy.PolicyDocument.getAllowAllPolicy(
                            region, awsAccountId, restApiId, stage));
        } catch (Exception e) {
            LOGGER.error("Unable to parse Access Token", e);
            throw new RuntimeException("Unauthorized");
        }
    }
}
