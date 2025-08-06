package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static java.util.Collections.singletonList;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class ReverificationResultService {
    public static final int MAX_RETRIES = 2;
    private static final Logger LOG = LogManager.getLogger(ReverificationResultService.class);
    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;
    private static final Long CLIENT_ASSERTION_LIFETIME = 5L;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;

    public ReverificationResultService(
            ConfigurationService configurationService, KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public ReverificationResultService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.kmsConnectionService = new KmsConnectionService(configurationService);
    }

    public TokenResponse getToken(String authCode) {
        var tokenRequest = constructTokenRequest(authCode);
        return sendTokenRequest(tokenRequest);
    }

    private TokenRequest constructTokenRequest(String authCode) {
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
                        NowHelper.nowPlus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES),
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

    private TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        LOG.info("Sending IPV token request");
        int count = 0;
        TokenResponse tokenResponse =
                new TokenResponse() {
                    @Override
                    public boolean indicatesSuccess() {
                        return false;
                    }

                    @Override
                    public HTTPResponse toHTTPResponse() {
                        return null;
                    }
                };

        while (count < MAX_RETRIES) {
            count++;
            try {
                var httpRequest = tokenRequest.toHTTPRequest();

                LOG.info("Sending IPV token request to {}", httpRequest.getURI());

                httpRequest.setConnectTimeout(1000);
                httpRequest.setReadTimeout(60 * 1000);

                var httpResponse = httpRequest.send();

                tokenResponse = TokenResponse.parse(httpResponse);

                if (tokenResponse.indicatesSuccess()) {
                    return tokenResponse;
                } else {
                    var response = tokenResponse.toErrorResponse();
                    LOG.warn(
                            "Unsuccessful {} response from IPV token endpoint on attempt: {}; error: {}",
                            response.toHTTPResponse().getStatusCode(),
                            count,
                            httpResponse.getContent());
                }
            } catch (IOException e) {
                LOG.error("Error whilst sending TokenRequest", e);
            } catch (com.nimbusds.oauth2.sdk.ParseException e) {
                LOG.error("Error whilst parsing TokenResponse", e);
            } catch (Exception e) {
                LOG.error("Unexpected error", e);
            }
        }

        // return all retries failed error
        return tokenResponse;
    }

    public HTTPResponse sendIpvReverificationRequest(UserInfoRequest userInfoRequest)
            throws UnsuccessfulReverificationResponseException {
        try {
            LOG.info("Sending IPV userinfo request");
            int count = 0;
            int maxTries = 2;
            HTTPResponse response;
            do {
                if (count > 0) LOG.warn("Retrying IPV reverification request");
                count++;
                response = userInfoRequest.toHTTPRequest().send();
                if (!response.indicatesSuccess()) {
                    LOG.warn(
                            "Unsuccessful {} response from IPV reverification endpoint on attempt{}: {} ",
                            response.getStatusCode(),
                            count,
                            response.getContent());
                }
            } while (!response.indicatesSuccess() && count < maxTries);
            if (!response.indicatesSuccess()) {
                throw new UnsuccessfulReverificationResponseException(
                        String.format(
                                "Error %s when attempting to call IPV reverification endpoint: %s",
                                response.getStatusCode(), response.getContent()));
            }
            LOG.info("Received successful reverification response");
            return response;
        } catch (IOException e) {
            throw new UnsuccessfulReverificationResponseException(
                    "Error when attempting to call IPV reverification endpoint", e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            var signingKeyId =
                    kmsConnectionService
                            .getPublicKey(
                                    GetPublicKeyRequest.builder()
                                            .keyId(
                                                    configurationService
                                                            .getMfaResetJarSigningKeyId())
                                            .build())
                            .keyId();

            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(hashSha256String(signingKeyId))
                            .build();

            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(configurationService.getMfaResetJarSigningKeyAlias())
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();

            var signResponse = kmsConnectionService.sign(signRequest);
            LOG.info("PrivateKeyJWT signed successfully");
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
