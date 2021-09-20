package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.util.List;

import static java.lang.Thread.sleep;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.WARMUP_HEADER;

public class AuthoriseAccessTokenHandler
        implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthoriseAccessTokenHandler.class);

    private final TokenValidationService tokenValidationService;
    private final ConfigurationService configurationService;
    private final DynamoService dynamoService;
    private final DynamoClientService clientService;

    public AuthoriseAccessTokenHandler(
            TokenValidationService tokenValidationService,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            DynamoClientService clientService) {
        this.tokenValidationService = tokenValidationService;
        this.configurationService = configurationService;
        this.dynamoService = dynamoService;
        this.clientService = clientService;
    }

    public AuthoriseAccessTokenHandler() {
        configurationService = new ConfigurationService();
        tokenValidationService =
                new TokenValidationService(
                        configurationService, new KmsConnectionService(configurationService));
        dynamoService = new DynamoService(configurationService);
        clientService =
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public AuthPolicy handleRequest(TokenAuthorizerContext input, Context context) {
        if (input.getType().equals(WARMUP_HEADER)) {
            LOGGER.info("Warmup Request Received {}", input.getAuthorizationToken());
            try {
                sleep(configurationService.getWarmupDelayMillis());
            } catch (InterruptedException e) {
                LOGGER.error("Sleep was interrupted", e);
                throw new RuntimeException("Sleep was interrupted", e);
            }
            LOGGER.info("Instance warmed for request {}", input.getAuthorizationToken());
            throw new RuntimeException("Unauthorized");
        } else {
            LOGGER.info("Request received in AuthoriseAccessTokenHandler");
            try {
                String token = input.getAuthorizationToken();

                AccessToken accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
                JWTClaimsSet claimsSet = SignedJWT.parse(accessToken.getValue()).getJWTClaimsSet();

                boolean isAccessTokenSignatureValid =
                        tokenValidationService.validateAccessTokenSignature(accessToken);
                if (!isAccessTokenSignatureValid) {
                    LOGGER.error("Access Token signature is not valid");
                    throw new RuntimeException("Unauthorized");
                }
                LOGGER.info("Successfully validated Access Token signature");

                List<String> scopeList = claimsSet.getStringListClaim("scope");
                if (scopeList == null
                        || !scopeList.contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
                    LOGGER.error("Access Token scope is not valid");
                    throw new RuntimeException("Unauthorized");
                }
                LOGGER.info("Successfully validated Access Token scope");
                String clientId = claimsSet.getStringClaim("client_id");
                if (clientId == null) {
                    LOGGER.error("Access Token client_id is missing");
                    throw new RuntimeException("Unauthorized");
                }
                if (!clientService.isValidClient(clientId)) {
                    LOGGER.error(
                            "Access Token client_id does not exist in Dynamo. ClientId {}",
                            clientId);
                    throw new RuntimeException("Unauthorized");
                }
                String subject = claimsSet.getSubject();
                if (subject == null) {
                    LOGGER.error("Access Token subject is missing");
                    throw new RuntimeException("Unauthorized");
                }
                try {
                    dynamoService.getUserProfileFromPublicSubject(subject);
                } catch (Exception e) {
                    LOGGER.error(
                            "Unable to retrieve UserProfile from Dynamo with given SubjectID: {}",
                            subject,
                            e);
                    throw new RuntimeException("Unauthorized");
                }
                LOGGER.info("User found in Dynamo with given SubjectID");
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
            } catch (ParseException | java.text.ParseException e) {
                LOGGER.error("Unable to parse Access Token", e);
                throw new RuntimeException("Unauthorized");
            }
        }
    }
}
