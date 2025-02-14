package uk.gov.di.authentication.ipv.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import io.github.resilience4j.retry.MaxRetriesExceededException;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.exceptions.HttpRequestErrorException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Predicate;

import static java.lang.String.format;
import static java.util.Collections.singletonList;

public class IPVTokenService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private final JwksService jwksService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final Logger LOG = LogManager.getLogger(IPVTokenService.class);

    public IPVTokenService(
            ConfigurationService configurationService, KmsConnectionService kmsService) {
        this(configurationService, kmsService, new JwksService(configurationService, kmsService));
    }

    public IPVTokenService(
            ConfigurationService configurationService,
            KmsConnectionService kmsService,
            JwksService jwksService) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
        this.jwksService = jwksService;
    }

    public TokenResponse getToken(String authCode) {
        var tokenRequest = constructTokenRequest(authCode);
        return retrySendTokenRequest(tokenRequest);
    }

    public TokenRequest constructTokenRequest(String authCode) {
        LOG.info("Constructing IPV token request");
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getIPVAuthorisationCallbackURI());
        var ipvBackendURI = configurationService.getIPVBackendURI();
        var ipvTokenURI = ConstructUriHelper.buildURI(ipvBackendURI.toString(), "token");
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getIPVAuthorisationClientId()),
                        singletonList(new Audience(configurationService.getIPVAudience())),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest(
                ipvTokenURI,
                generatePrivateKeyJwt(claimsSet),
                codeGrant,
                null,
                null,
                Map.of(
                        "client_id",
                        singletonList(configurationService.getIPVAuthorisationClientId())));
    }

    // TODO - AUT-4009 - Extract this to a retrying service in 'shared'
    public <T> T retryTask(
            RetryConfig.Builder<Object> retryConfigBuilder, String description, Callable<T> task)
            throws Exception {
        LOG.info("Retrying '{}'", description);
        retryConfigBuilder.failAfterMaxAttempts(true);
        RetryConfig retryConfig = retryConfigBuilder.build();
        RetryRegistry registry = RetryRegistry.of(retryConfig);
        Retry retry = registry.retry(description);

        Callable<T> retryLoggingWrapper =
                () -> {
                    LOG.info(
                            "'{}' attempt {} of {}",
                            description,
                            retry.getMetrics().getNumberOfTotalCalls(),
                            retryConfig.getMaxAttempts());
                    return task.call();
                };

        try {
            return retry.executeCallable(retryLoggingWrapper);
        } catch (MaxRetriesExceededException e) {
            LOG.warn(
                    "Maximum {} retries exceeded for '{}'",
                    retryConfig.getMaxAttempts(),
                    description,
                    e);
            throw e;
        }
    }

    // TODO - AUT-4009 - We should think about what we do with these exceptions. We shouldn't throw
    //  them up to the lambda. Instead, we should return a nicer error.
    // TODO - AUT-4009 - Make this private - we should only need to test the class entrypoint
    public TokenResponse retrySendTokenRequest(TokenRequest tokenRequest) {
        Predicate<Throwable> httpErrorPredicate =
                hep ->
                        (hep instanceof HttpRequestErrorException)
                                && ((HttpRequestErrorException) hep).getErrorCode() >= 500
                                && ((HttpRequestErrorException) hep).getErrorCode() < 600;

        var retryConfigBuilder =
                RetryConfig.custom().maxAttempts(2).retryOnException(httpErrorPredicate);

        try {
            return retryTask(
                    retryConfigBuilder, "sendTokenRequest", () -> sendTokenRequest(tokenRequest));
        } catch (MaxRetriesExceededException e) {
            // TODO - AUT-4009 - Add any necessary abandon handling. What happens when we abandon?
            throw new RuntimeException(e);
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        } catch (Exception e) {
            // TODO - AUT-4009 - Currently swallowing this exception
            //  Figure out a better way of handling this (and other) errors
            LOG.error("Unhandled Exception", e);
            return null;
        }

        // TODO - AUT-4009 - what happens when we error out in a different way?
        // TODO - AUT-4009 - is this a graceful way of handling the io/parse exceptions?
    }

    private TokenResponse sendTokenRequest(TokenRequest tokenRequest)
            throws IOException, ParseException {
        var httpRequest = tokenRequest.toHTTPRequest();
        httpRequest.setConnectTimeout(500);
        httpRequest.setReadTimeout(2000);
        // TODO - AUT-4009 - This may need to be adjusted. In this case, we might be better timing
        //  out after 25s and handling the fallout - that's what usually happens when IPV has
        //  issues. IPV also takes a long time in general, so having a short timeout might not be
        //  great.
        var httpResponse = httpRequest.send();

        if (!httpResponse.indicatesSuccess())
            throw new HttpRequestErrorException(httpResponse.getStatusCode());

        return TokenResponse.parse(httpResponse);
    }

    public UserInfo sendIpvUserIdentityRequest(UserInfoRequest userInfoRequest)
            throws UnsuccessfulCredentialResponseException {
        try {
            LOG.info("Sending IPV userinfo request");
            int count = 0;
            int maxTries = 2;
            UserInfoResponse userIdentityResponse;
            do {
                if (count > 0) LOG.warn("Retrying IPV user identity request");
                count++;
                var httpResponse = userInfoRequest.toHTTPRequest().send();
                userIdentityResponse = UserInfoResponse.parse(httpResponse);
                if (!httpResponse.indicatesSuccess()) {
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from IPV user identity endpoint on attempt %d: %s ",
                                    httpResponse.getStatusCode(),
                                    count,
                                    httpResponse.getContent()));
                }
            } while (!userIdentityResponse.indicatesSuccess() && count < maxTries);

            if (!userIdentityResponse.indicatesSuccess()) {
                LOG.error("Response from user-identity does not indicate success");
                throw new UnsuccessfulCredentialResponseException(
                        userIdentityResponse.toErrorResponse().toString());
            } else {
                return userIdentityResponse.toSuccessResponse().getUserInfo();
            }
        } catch (ParseException e) {
            LOG.error("Error when attempting to parse HTTPResponse to UserInfoResponse");
            throw new UnsuccessfulCredentialResponseException(
                    "Error when attempting to parse http response to UserInfoResponse");
        } catch (IOException e) {
            LOG.error("Error when attempting to call IPV user-identity endpoint", e);
            throw new RuntimeException(e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            var signingJwk = jwksService.getPublicIpvTokenJwkWithOpaqueId();
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM).keyID(signingJwk.getKeyID()).build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(configurationService.getIPVTokenSigningKeyAlias())
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();

            var signResponse = kmsService.sign(signRequest);
            LOG.info("PrivateKeyJWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResponse.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return new PrivateKeyJWT(SignedJWT.parse(message + "." + signature));
        } catch (JOSEException | java.text.ParseException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}
