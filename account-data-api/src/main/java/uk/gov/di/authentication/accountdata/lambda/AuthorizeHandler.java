package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
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
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class AuthorizeHandler
        implements RequestHandler<APIGatewayCustomAuthorizerEvent, Map<String, Object>> {
    private static final Logger LOG = LogManager.getLogger(AuthorizeHandler.class);
    private RemoteJwksService jwksService;

    public AuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public AuthorizeHandler(ConfigurationService configurationService) {
        try {
            this.jwksService = new RemoteJwksService(configurationService.getAccountDataJwksUrl());
        } catch (MalformedURLException e) {
            LOG.error("Unable to initialise authorize handler, malformed account data jwks url");
            throw new AuthorizeException(e.getMessage());
        }
    }

    public AuthorizeHandler(RemoteJwksService jwksService) {
        this.jwksService = jwksService;
    }

    @Override
    public Map<String, Object> handleRequest(
            APIGatewayCustomAuthorizerEvent apiGatewayCustomAuthorizerEvent, Context context) {
        var token = apiGatewayCustomAuthorizerEvent.getAuthorizationToken();
        try {
            var accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            var signedAccessToken = SignedJWT.parse(accessToken.getValue());
            var claimsSet = signedAccessToken.getJWTClaimsSet();

            var maybeValidationFailure =
                    validateAccessTokenExpiryTime(claimsSet)
                            .flatMap(success -> verifySignature(signedAccessToken));

            if (maybeValidationFailure.isFailure()) {
                throw maybeValidationFailure.getFailure();
            }

            var subject = signedAccessToken.getJWTClaimsSet().getSubject();
            var methodArn = apiGatewayCustomAuthorizerEvent.getMethodArn();
            return getAllowExecuteApiPolicyForSubject(subject, methodArn);
        } catch (ParseException | java.text.ParseException e) {
            throw new RuntimeException("TODO");
        }
    }

    private Result<UnauthorizedException, Void> verifySignature(SignedJWT signedJWT) {
        try {
            var maybeJwk =
                    jwksService.retrieveJwkFromURLWithKeyId(signedJWT.getHeader().getKeyID());

            if (maybeJwk.isFailure()) {
                LOG.warn("Error retrieving jwks key: {}", maybeJwk.getFailure());
                return Result.failure(new UnauthorizedException());
            }
            var jwk = maybeJwk.getSuccess();
            var algorithm = signedJWT.getHeader().getAlgorithm();

            JWSVerifier verifier;
            if (JWSAlgorithm.ES256.equals(algorithm)) {
                verifier = new ECDSAVerifier(jwk.toECKey());
            } else {
                throw new RuntimeException("TODO");
            }

            if (!signedJWT.verify(verifier)) {
                return Result.failure(new UnauthorizedException());
            } else {
                return Result.success(null);
            }
        } catch (JOSEException e) {
            throw new RuntimeException("TODO");
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

    private Map<String, Object> getAllowExecuteApiPolicyForSubject(
            String subject, String methodArn) {
        var executeApiStatement =
                Map.ofEntries(
                        Map.entry("Action", "execute-api:Invoke"),
                        Map.entry("Effect", "Allow"),
                        Map.entry("Resource", methodArn));
        return Map.ofEntries(
                Map.entry("principalId", subject),
                Map.entry(
                        "policyDocument",
                        Map.ofEntries(
                                Map.entry("Version", "2012-10-17"),
                                Map.entry("Statement", List.of(executeApiStatement)))));
    }
}
