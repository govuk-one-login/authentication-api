package uk.gov.di.orchestration.identity.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.JWK;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;

import static java.util.Collections.singletonList;

public class IdentityTokenService {

    private static final Logger LOG = LogManager.getLogger(IdentityTokenService.class);
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private final KmsConnectionService kmsService;
    private final URI callbackUri;
    private final URI tokenUri;
    private final String clientId;
    private final String audience;
    private final JWK signingJwk;
    private final String signingKeyAlias;

    public IdentityTokenService(
            KmsConnectionService kmsService,
            URI callbackUri,
            URI backendUri,
            String clientId,
            String audience,
            JWK signingJwk,
            String signingKeyAlias) {
        this.kmsService = kmsService;
        this.callbackUri = callbackUri;
        this.tokenUri = ConstructUriHelper.buildURI(backendUri.toString(), "token");
        this.clientId = clientId;
        this.audience = audience;
        this.signingJwk = signingJwk;
        this.signingKeyAlias = signingKeyAlias;
    }

    public TokenResponse getToken(String authCode) {
        int count = 0;
        int maxTries = 2;
        TokenResponse tokenResponse;
        do {
            if (count > 0) LOG.warn("Retrying access token request");
            count++;
            // We must generate a new token request every time:
            // private_key_jwt client auth JWTs are not reusable
            var tokenRequest = constructTokenRequest(authCode);
            tokenResponse = sendTokenRequest(tokenRequest);
            if (!tokenResponse.indicatesSuccess()) {
                HTTPResponse response = tokenResponse.toHTTPResponse();
                LOG.warn(
                        "Unsuccessful {} response from token endpoint on attempt {}: {} ",
                        response.getStatusCode(),
                        count,
                        response.getBody());
            }
        } while (!tokenResponse.indicatesSuccess() && count < maxTries);

        return tokenResponse;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        LOG.info("Constructing token request");
        var codeGrant = new AuthorizationCodeGrant(new AuthorizationCode(authCode), callbackUri);
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(clientId),
                        singletonList(new Audience(audience)),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest.Builder(tokenUri, generatePrivateKeyJwt(claimsSet), codeGrant)
                .customParameter("client_id", clientId)
                .build();
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            LOG.info("Sending token request");
            return TokenResponse.parse(tokenRequest.toHTTPRequest().send());
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new RuntimeException(e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
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
                            .keyId(signingKeyAlias)
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
