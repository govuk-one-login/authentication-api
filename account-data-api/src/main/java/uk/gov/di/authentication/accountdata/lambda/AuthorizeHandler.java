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
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.util.List;
import java.util.Optional;

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
        var methodArn = apiGatewayCustomAuthorizerEvent.getMethodArn();
        var httpMethod = extractHttpMethod(methodArn);

        try {
            var accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            var signedAccessToken = SignedJWT.parse(accessToken.getValue());
            var claimsSet = signedAccessToken.getJWTClaimsSet();

            var subject =
                    validateToken(signedAccessToken, claimsSet, httpMethod)
                            .map(JWTClaimsSet::getSubject)
                            .orElseThrow(UnauthorizedException::new);

            LOG.info("Request validated, returning access policy");
            return getAllowExecuteApiPolicyForSubject(subject, methodArn);
        } catch (ParseException | java.text.ParseException e) {
            LOG.warn("Unable to parse Access Token {}", e.getMessage());
            throw new UnauthorizedException();
        }
    }

    private Optional<JWTClaimsSet> validateToken(
            SignedJWT signedAccessToken, JWTClaimsSet claimsSet, String httpMethod) {
        if (!verifySignature(signedAccessToken)) {
            return Optional.empty();
        }

        return Optional.of(claimsSet)
                .filter(c -> !DateUtils.isBefore(c.getExpirationTime(), NowHelper.now(), 0))
                .filter(c -> c.getSubject() != null && !c.getSubject().isEmpty())
                .filter(c -> configurationService.getAuthIssuerClaim().equals(c.getIssuer()))
                .filter(
                        c ->
                                c.getAudience()
                                        .contains(
                                                configurationService
                                                        .getAuthToAccountDataApiAudience()))
                .filter(
                        c ->
                                c.getNotBeforeTime() == null
                                        || !DateUtils.isAfter(
                                                c.getNotBeforeTime(), NowHelper.now(), 0))
                .filter(this::isClientIdValid)
                .filter(c -> isScopeValidForMethod(c, httpMethod))
                .filter(this::isScopePermittedForClient);
    }

    private boolean verifySignature(SignedJWT signedJWT) {
        try {
            var jwkResult =
                    jwksService.retrieveJwkFromURLWithKeyId(signedJWT.getHeader().getKeyID());

            if (jwkResult.isFailure()) {
                LOG.warn("Error retrieving jwks key: {}", jwkResult.getFailure());
                return false;
            }
            var jwk = jwkResult.getSuccess();
            var algorithm = signedJWT.getHeader().getAlgorithm();

            if (!JWSAlgorithm.ES256.equals(algorithm)) {
                LOG.error("Unsupported signature algorithm: {}", algorithm);
                return false;
            }

            JWSVerifier verifier = new ECDSAVerifier(jwk.toECKey());
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            LOG.error("Error verifying signature: {}", e.getMessage());
            return false;
        }
    }

    private boolean isClientIdValid(JWTClaimsSet claimsSet) {
        var clientId = (String) claimsSet.getClaim("client_id");
        return configurationService.getAMCClientId().equals(clientId)
                || configurationService.getHomeClientId().equals(clientId);
    }

    private boolean isScopeValidForMethod(JWTClaimsSet claimsSet, String httpMethod) {
        return AccountDataScope.fromValue((String) claimsSet.getClaim("scope"))
                .map(
                        scope ->
                                switch (scope) {
                                    case PASSKEY_RETRIEVE -> "GET".equals(httpMethod);
                                    case PASSKEY_CREATE -> "POST".equals(httpMethod);
                                    case PASSKEY_UPDATE -> "PATCH".equals(httpMethod);
                                    case PASSKEY_DELETE -> "DELETE".equals(httpMethod);
                                })
                .orElse(false);
    }

    private boolean isScopePermittedForClient(JWTClaimsSet claimsSet) {
        var clientId = (String) claimsSet.getClaim("client_id");
        if (!configurationService.getAMCClientId().equals(clientId)) {
            return true;
        }
        return AccountDataScope.fromValue((String) claimsSet.getClaim("scope"))
                .map(
                        scope ->
                                scope == AccountDataScope.PASSKEY_RETRIEVE
                                        || scope == AccountDataScope.PASSKEY_CREATE)
                .orElse(false);
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
}
