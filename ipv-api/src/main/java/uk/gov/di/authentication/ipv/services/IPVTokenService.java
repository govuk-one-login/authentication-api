package uk.gov.di.authentication.ipv.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.helpers.ConstructUriHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

import static java.util.Collections.singletonList;

public class IPVTokenService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    public static final String IPV_ACCESS_TOKEN_PREFIX = "IPV_ACCESS_TOKEN:";
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final Logger LOG = LogManager.getLogger(IPVTokenService.class);

    public IPVTokenService(
            ConfigurationService configurationService, KmsConnectionService kmsService) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getIPVAuthorisationCallbackURI());
        var ipvBackendURI = configurationService.getIPVBackendURI();
        var ipvTokenURI = ConstructUriHelper.buildURI(ipvBackendURI.toString(), "token");
        var expiryDate = LocalDateTime.now().plus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES);
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getIPVAuthorisationClientId()),
                        singletonList(new Audience(ipvTokenURI)),
                        Date.from(expiryDate.atZone(ZoneId.of("UTC")).toInstant()),
                        null,
                        Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()),
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
            return TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
    }

    public String sendIpvUserIdentityRequest(AccessToken accessToken) {
        try {
            var ipvBackendURI = configurationService.getIPVBackendURI();
            var userIdentityURI =
                    ConstructUriHelper.buildURI(ipvBackendURI.toString(), "user-identity");
            var userInfoRequest = new UserInfoRequest(userIdentityURI, accessToken);
            var response = userInfoRequest.toHTTPRequest().send();
            if (response.indicatesSuccess()) {
                var contentAsJSONObject = response.getContentAsJSONObject();
                LOG.info(
                        "THIS NEEDS TO REMOVED. THIS IS FOR DEBUGGING PURPOSES: {}",
                        contentAsJSONObject.toJSONString());
                return contentAsJSONObject.toJSONString();
            } else {
                LOG.error("Response from user-identity does not indicate success");
                throw new RuntimeException();
            }
        } catch (IOException | ParseException e) {
            LOG.error("Error when attempting to call IPV user-identity endpoint");
            throw new RuntimeException();
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(configurationService.getIPVTokenSigningKeyAlias())
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var messageToSign = ByteBuffer.wrap(message.getBytes());
            var signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(configurationService.getIPVTokenSigningKeyAlias());
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsService.sign(signRequest);
            LOG.info("PrivateKeyJWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return new PrivateKeyJWT(SignedJWT.parse(message + "." + signature));
        } catch (JOSEException | java.text.ParseException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }
}
