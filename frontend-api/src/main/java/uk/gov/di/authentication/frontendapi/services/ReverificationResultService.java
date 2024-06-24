package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.exceptions.JwtParseException;
import uk.gov.di.authentication.shared.exceptions.TokenRequestException;
import uk.gov.di.authentication.shared.exceptions.TokenResponseException;
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

public class ReverificationResultService {

    private static final Logger LOG = LogManager.getLogger(ReverificationResultService.class);
    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsConnectionService;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
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
                singletonList(ipvTokenURI),
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
            } while (!tokenResponse.indicatesSuccess() && count < maxTries);

            return tokenResponse;
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new TokenRequestException("Error whilst sending TokenRequest", e);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new TokenResponseException("Error whilst parsing TokenResponse", e);
        }
    }

    public UserInfo sendIpvReverificationRequest(UserInfoRequest userInfoRequest)
            throws UnsuccessfulReverificationResponseException {
        try {
            LOG.info("Sending IPV userinfo request");
            int count = 0;
            int maxTries = 2;
            UserInfoResponse reverficationResponse;
            do {
                if (count > 0) LOG.warn("Retrying IPV reverification request");
                count++;
                var httpResponse = userInfoRequest.toHTTPRequest().send();
                reverficationResponse = UserInfoResponse.parse(httpResponse);
            } while (!reverficationResponse.indicatesSuccess() && count < maxTries);

            if (!reverficationResponse.indicatesSuccess()) {
                LOG.error("Response from reverification does not indicate success");
                throw new UnsuccessfulReverificationResponseException(
                        reverficationResponse.toErrorResponse().toString());
            } else {
                return reverficationResponse.toSuccessResponse().getUserInfo();
            }
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Error when attempting to parse HTTPResponse to reverficationResponse");
            throw new UnsuccessfulReverificationResponseException(
                    "Error when attempting to parse http response to reverficationResponse");
        } catch (IOException e) {
            LOG.error("Error when attempting to call IPV reverification endpoint", e);
            throw new UnsuccessfulReverificationResponseException(
                    "Error when attempting to call IPV reverification endpoint");
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(configurationService.getMfaResetStorageTokenSigningKeyAlias())
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var signRequest =
                    SignRequest.builder()
                            .message(
                                    SdkBytes.fromByteArray(
                                            message.getBytes(StandardCharsets.UTF_8)))
                            .keyId(configurationService.getMfaResetStorageTokenSigningKeyAlias())
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
            throw new JwtParseException(
                    "Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
        }
    }
}
