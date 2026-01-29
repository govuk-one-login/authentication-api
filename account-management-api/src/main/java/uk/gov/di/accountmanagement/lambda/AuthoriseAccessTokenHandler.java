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
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static uk.gov.di.accountmanagement.entity.AuthPolicy.PolicyDocument.getAllowAllPolicy;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class AuthoriseAccessTokenHandler
        implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    private static final Logger LOG = LogManager.getLogger(AuthoriseAccessTokenHandler.class);

    private final TokenValidationService tokenValidationService;

    public AuthoriseAccessTokenHandler(TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    public AuthoriseAccessTokenHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthoriseAccessTokenHandler(ConfigurationService configurationService) {
        tokenValidationService =
                new TokenValidationService(
                        new JwksService(
                                configurationService,
                                new KmsConnectionService(configurationService)),
                        configurationService);
    }

    @Override
    public AuthPolicy handleRequest(TokenAuthorizerContext input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> authoriseAccessTokenHandler(input));
    }

    public AuthPolicy authoriseAccessTokenHandler(TokenAuthorizerContext input) {
        attachTraceId();
        LOG.info("Request received in AuthoriseAccessTokenHandler");
        try {
            String token = input.getAuthorizationToken();

            AccessToken accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            SignedJWT signedAccessToken = SignedJWT.parse(accessToken.getValue());
            JWTClaimsSet claimsSet = signedAccessToken.getJWTClaimsSet();

            Date currentDateTime = NowHelper.now();
            if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
                LOG.warn(
                        "Access Token expires at: {}. CurrentDateTime is: {}",
                        claimsSet.getExpirationTime(),
                        currentDateTime);
                throw new RuntimeException("Unauthorized");
            }
            boolean isAccessTokenSignatureValid =
                    tokenValidationService.validateAccessTokenSignature(accessToken);
            if (!isAccessTokenSignatureValid) {
                LOG.warn("Access Token signature is not valid");
                throw new RuntimeException("Unauthorized");
            }
            LOG.info("Successfully validated Access Token signature");

            List<String> scopeList = claimsSet.getStringListClaim("scope");
            if (scopeList == null
                    || !scopeList.contains(CustomScopeValue.ACCOUNT_MANAGEMENT.getValue())) {
                LOG.warn("Access Token scope is not valid or missing");
                throw new RuntimeException("Unauthorized");
            }
            LOG.info("Successfully validated Access Token scope");
            String clientId = claimsSet.getStringClaim("client_id");
            if (clientId == null) {
                LOG.warn("Access Token client_id is missing");
                throw new RuntimeException("Unauthorized");
            }
            String subject = claimsSet.getSubject();
            if (subject == null) {
                LOG.warn("Access Token subject is missing");
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

            LOG.info("Generating context");
            Map<String, Object> context = Map.of("clientId", clientId);

            LOG.info("Generating AuthPolicy");
            return new AuthPolicy(
                    subject, getAllowAllPolicy(region, awsAccountId, restApiId, stage), context);
        } catch (ParseException | java.text.ParseException e) {
            LOG.warn("Unable to parse Access Token {}", e.getMessage());
            throw new RuntimeException("Unauthorized");
        }
    }
}
