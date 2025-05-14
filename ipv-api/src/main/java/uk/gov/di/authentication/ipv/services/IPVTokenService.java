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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
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
        return sendTokenRequest(tokenRequest);
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
                null,
                null,
                Map.of(
                        "client_id",
                        singletonList(configurationService.getIPVAuthorisationClientId())));
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            LOG.info("Sending IPV token request");
            int count = 0;
            int maxTries = 2;
            TokenResponse tokenResponse;
            do {
                if (count > 0) LOG.warn("Retrying IPV access token request");
                count++;
                tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());
                if (!tokenResponse.indicatesSuccess()) {
                    HTTPResponse response = tokenResponse.toHTTPResponse();
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from IPV token endpoint on attempt %d: %s ",
                                    response.getStatusCode(), count, response.getBody()));
                }
            } while (!tokenResponse.indicatesSuccess() && count < maxTries);

            return tokenResponse;
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
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
                                    httpResponse.getStatusCode(), count, httpResponse.getBody()));
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
