package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static java.lang.Thread.sleep;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.WARMUP_HEADER;

public class AuthoriseAccessTokenHandler
        implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    private static final Logger LOG = LogManager.getLogger(AuthoriseAccessTokenHandler.class);

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
        configurationService = ConfigurationService.getInstance();
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
            LOG.info("Warmup Request Received");
            try {
                sleep(configurationService.getWarmupDelayMillis());
            } catch (InterruptedException e) {
                LOG.error("Sleep was interrupted", e);
                throw new RuntimeException("Sleep was interrupted", e);
            }
            LOG.info("Instance warmed for request");
            throw new RuntimeException("Unauthorized");
        } else {
            LOG.info("Request received in AuthoriseAccessTokenHandler");
            try {
                String token = input.getAuthorizationToken();

                AccessToken accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
                SignedJWT signedAccessToken = SignedJWT.parse(accessToken.getValue());
                JWTClaimsSet claimsSet = signedAccessToken.getJWTClaimsSet();

                LocalDateTime localDateTime = LocalDateTime.now();
                Date currentDateTime =
                        Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
                if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
                    LOG.error(
                            "Access Token expires at: {}. CurrentDateTime is: {}",
                            claimsSet.getExpirationTime(),
                            currentDateTime);
                    throw new RuntimeException("Unauthorized");
                }
                boolean isAccessTokenSignatureValid =
                        tokenValidationService.validateAccessTokenSignature(accessToken);
                if (!isAccessTokenSignatureValid) {
                    LOG.error("Access Token signature is not valid");
                    throw new RuntimeException("Unauthorized");
                }
                LOG.info("Successfully validated Access Token signature");

                List<String> scopeList = claimsSet.getStringListClaim("scope");
                if (scopeList == null
                        || !scopeList.contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
                    LOG.error("Access Token scope is not valid or missing");
                    throw new RuntimeException("Unauthorized");
                }
                LOG.info("Successfully validated Access Token scope");
                String clientId = claimsSet.getStringClaim("client_id");
                if (clientId == null) {
                    LOG.error("Access Token client_id is missing");
                    throw new RuntimeException("Unauthorized");
                }
                if (!clientService.isValidClient(clientId)) {
                    LOG.error(
                            "Access Token client_id does not exist in Dynamo. ClientId {}",
                            clientId);
                    throw new RuntimeException("Unauthorized");
                }
                String subject = claimsSet.getSubject();
                if (subject == null) {
                    LOG.error("Access Token subject is missing");
                    throw new RuntimeException("Unauthorized");
                }
                try {
                    dynamoService.getUserProfileFromPublicSubject(subject);
                } catch (Exception e) {
                    LOG.error("Unable to retrieve UserProfile from Dynamo with given SubjectID");
                    throw new RuntimeException("Unauthorized");
                }
                LOG.info("User found in Dynamo with given SubjectID");
                String methodArn = input.getMethodArn();
                String[] arnPartials = methodArn.split(":");
                String region = arnPartials[3];
                String awsAccountId = arnPartials[4];
                String[] apiGatewayArnPartials = arnPartials[5].split("/");
                String restApiId = apiGatewayArnPartials[0];
                String stage = apiGatewayArnPartials[1];
                LOG.info("Generating AuthPolicy");
                return new AuthPolicy(
                        subject,
                        AuthPolicy.PolicyDocument.getAllowAllPolicy(
                                region, awsAccountId, restApiId, stage));
            } catch (ParseException | java.text.ParseException e) {
                LOG.error("Unable to parse Access Token");
                throw new RuntimeException("Unauthorized");
            }
        }
    }
}
