package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.AuthorizeException;
import uk.gov.di.authentication.accountdata.entity.UnauthorizedException;
import uk.gov.di.authentication.accountdata.services.RemoteJwksService;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.util.Date;
import java.util.List;

public class AuthorizeHandler
        implements RequestHandler<APIGatewayCustomAuthorizerEvent, IamPolicyResponseV1> {
    private static final Logger LOG = LogManager.getLogger(AuthorizeHandler.class);
    private final ConfigurationService configurationService;
    private RemoteJwksService jwksService;

    public AuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthorizeHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        try {
            this.jwksService = new RemoteJwksService(configurationService.getAccountDataJwksUrl());
        } catch (MalformedURLException e) {
            LOG.error("Unable to initialise authorize handler, malformed account data jwks url");
            throw new AuthorizeException(e.getMessage());
        }
    }

    public AuthorizeHandler(RemoteJwksService jwksService) {
        this.configurationService = ConfigurationService.getInstance();
        this.jwksService = jwksService;
    }

    public AuthorizeHandler(
            ConfigurationService configurationService, RemoteJwksService jwksService) {
        this.configurationService = configurationService;
        this.jwksService = jwksService;
    }

    @Override
    public IamPolicyResponseV1 handleRequest(
            APIGatewayCustomAuthorizerEvent apiGatewayCustomAuthorizerEvent, Context context) {
        var token = apiGatewayCustomAuthorizerEvent.getAuthorizationToken();
        try {
            var accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            var signedAccessToken = SignedJWT.parse(accessToken.getValue());
            var claimsSet = signedAccessToken.getJWTClaimsSet();

            var validatedClaimsResult =
                    validateAccessTokenExpiryTime(claimsSet)
                            .flatMap(success -> verifySignature(signedAccessToken))
                            .flatMap(success -> validateClaimsSet(claimsSet));

            var methodArn = apiGatewayCustomAuthorizerEvent.getMethodArn();
            var httpMethod = extractHttpMethod(methodArn);

            var result =
                    validatedClaimsResult
                            .flatMap(claims -> validateScope(claims, httpMethod))
                            .map(JWTClaimsSet::getSubject);

            if (result.isFailure()) {
                throw result.getFailure();
            }

            LOG.info("Request validated, returning access policy");
            return getAllowExecuteApiPolicyForSubject(result.getSuccess(), methodArn);
        } catch (ParseException | java.text.ParseException e) {
            LOG.warn("Unable to parse Access Token {}", e.getMessage());
            throw new UnauthorizedException();
        }
    }

    private Result<UnauthorizedException, Void> verifySignature(SignedJWT signedJWT) {
        var failure = Result.<UnauthorizedException, Void>failure(new UnauthorizedException());
        try {
            var jwkResult =
                    jwksService.retrieveJwkFromURLWithKeyId(signedJWT.getHeader().getKeyID());

            if (jwkResult.isFailure()) {
                LOG.warn("Error retrieving jwks key: {}", jwkResult.getFailure());
                return failure;
            }
            var jwk = jwkResult.getSuccess();
            var algorithm = signedJWT.getHeader().getAlgorithm();

            JWSVerifier verifier;
            if (JWSAlgorithm.ES256.equals(algorithm)) {
                verifier = new ECDSAVerifier(jwk.toECKey());
            } else {
                LOG.error("Unsupported signature algorithm: {}", algorithm);
                return failure;
            }

            if (!signedJWT.verify(verifier)) {
                return failure;
            } else {
                return Result.success(null);
            }
        } catch (JOSEException e) {
            LOG.error("Error verifying signature: {}", e.getMessage());
            return failure;
        }
    }

    private Result<UnauthorizedException, Void> validateAccessTokenExpiryTime(
            JWTClaimsSet claimsSet) {
        Date currentDateTime = NowHelper.now();
        if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
            LOG.warn(
                    "Access Token expires at: {}. CurrentDateTime is: {}",
                    claimsSet.getExpirationTime(),
                    currentDateTime);
            return Result.failure(new UnauthorizedException());
        } else {
            return Result.success(null);
        }
    }

    private Result<UnauthorizedException, JWTClaimsSet> validateClaimsSet(JWTClaimsSet claimsSet) {
        if (claimsSet.getSubject() == null || claimsSet.getSubject().isEmpty()) {
            LOG.warn("Access Token subject is missing");
            return Result.failure(new UnauthorizedException());
        }
        var expectedIssuer = configurationService.getAuthIssuerClaim();
        if (!expectedIssuer.equals(claimsSet.getIssuer())) {
            LOG.warn("Access Token issuer is invalid");
            return Result.failure(new UnauthorizedException());
        }
        var expectedAudience = configurationService.getAuthToAccountDataApiAudience();
        if (!claimsSet.getAudience().contains(expectedAudience)) {
            LOG.warn("Access Token audience is invalid");
            return Result.failure(new UnauthorizedException());
        }
        if (claimsSet.getNotBeforeTime() != null
                && DateUtils.isAfter(claimsSet.getNotBeforeTime(), NowHelper.now(), 0)) {
            LOG.warn("Access Token is not yet valid (nbf: {})", claimsSet.getNotBeforeTime());
            return Result.failure(new UnauthorizedException());
        }
        var expectedClientId = configurationService.getAMCClientId();
        var homeClientId = configurationService.getHomeClientId();
        var clientId = (String) claimsSet.getClaim("client_id");
        if (!expectedClientId.equals(clientId) && !homeClientId.equals(clientId)) {
            LOG.warn("Access Token client_id is invalid");
            return Result.failure(new UnauthorizedException());
        }
        return Result.success(claimsSet);
    }

    private IamPolicyResponseV1 getAllowExecuteApiPolicyForSubject(
            String subject, String methodArn) {
        var statement = IamPolicyResponseV1.allowStatement(methodArn);

        var policyDocument =
                IamPolicyResponseV1.PolicyDocument.builder()
                        .withStatement(List.of(statement))
                        .withVersion(IamPolicyResponseV1.VERSION_2012_10_17)
                        .build();

        return IamPolicyResponseV1.builder()
                .withPolicyDocument(policyDocument)
                .withPrincipalId(subject)
                .build();
    }

    private String extractHttpMethod(String methodArn) {
        String[] parts = methodArn.split("/");
        if (parts.length < 3) {
            throw new UnauthorizedException();
        }
        return parts[2];
    }

    private Result<UnauthorizedException, JWTClaimsSet> validateScope(
            JWTClaimsSet claimsSet, String httpMethod) {
        var scopeValue = (String) claimsSet.getClaim("scope");
        var scope = AccountDataScope.fromValue(scopeValue);

        if (scope.isEmpty()) {
            LOG.warn("Invalid or missing scope: {}", scopeValue);
            return Result.failure(new UnauthorizedException());
        }

        boolean methodMatchesScope =
                (scope.get() == AccountDataScope.PASSKEY_RETRIEVE && "GET".equals(httpMethod))
                        || (scope.get() == AccountDataScope.PASSKEY_CREATE
                                && "POST".equals(httpMethod))
                        || (scope.get() == AccountDataScope.PASSKEY_UPDATE
                                && "PATCH".equals(httpMethod))
                        || (scope.get() == AccountDataScope.PASSKEY_DELETE
                                && "DELETE".equals(httpMethod));

        if (!methodMatchesScope) {
            LOG.warn("Scope {} not permitted for method {}", scopeValue, httpMethod);
            return Result.failure(new UnauthorizedException());
        }

        var clientId = (String) claimsSet.getClaim("client_id");
        var amcClientId = configurationService.getAMCClientId();
        if (amcClientId.equals(clientId)
                && scope.get() != AccountDataScope.PASSKEY_RETRIEVE
                && scope.get() != AccountDataScope.PASSKEY_CREATE) {
            LOG.warn("Client {} not permitted scope {}", clientId, scopeValue);
            return Result.failure(new UnauthorizedException());
        }

        return Result.success(claimsSet);
    }
}
