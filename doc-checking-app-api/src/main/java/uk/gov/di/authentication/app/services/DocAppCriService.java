package uk.gov.di.authentication.app.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.exception.UnsuccesfulCredentialResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.util.Collections.singletonList;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class DocAppCriService {

    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final String STAGING_ENVIRONMENT = "staging";
    private static final Logger LOG = LogManager.getLogger(DocAppCriService.class);

    public DocAppCriService(
            ConfigurationService configurationService, KmsConnectionService kmsService) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getDocAppAuthorisationCallbackURI());
        var backendURI = configurationService.getDocAppBackendURI();
        var tokenURI = buildURI(backendURI.toString(), "token");
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getDocAppAuthorisationClientId()),
                        singletonList(new Audience(tokenURI)),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest(
                tokenURI,
                generatePrivateKeyJwt(claimsSet),
                codeGrant,
                null,
                singletonList(tokenURI),
                Map.of(
                        "client_id",
                        singletonList(configurationService.getDocAppAuthorisationClientId())));
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

    public String sendCriDataRequest(AccessToken accessToken) {
        try {
            var criDataURI =
                    buildURI(
                            configurationService.getDocAppBackendURI().toString(),
                            configurationService.getDocAppCriDataEndpoint());

            var request = new HTTPRequest(GET, criDataURI);
            request.setAuthorization(accessToken.toAuthorizationHeader());

            var response = request.send();
            if (!response.indicatesSuccess()) {
                LOG.error(
                        "Error {} when attempting to call CRI data endpoint: {}",
                        response.getStatusCode(),
                        response.getContent());
                throw new UnsuccesfulCredentialResponseException(
                        "Error response received from CRI");
            }

            if (!isValidResponse(response)) {
                LOG.error("Invalid CRI response signature");
                throw new UnsuccesfulCredentialResponseException("Invalid CRI response signature");
            }
            return response.getContent();
        } catch (IOException e) {
            LOG.error("Error when attempting to call CRI data endpoint", e);
            throw new UnsuccesfulCredentialResponseException(
                    "Error when attempting to call CRI data endpoint", e);
        }
    }

    private boolean isValidResponse(HTTPResponse response) {
        try {
            JWT jwt = response.getContentAsJWT();
            if (jwt instanceof SignedJWT) {
                var signed = (SignedJWT) jwt;
                ECPublicKey signingPublicKey;
                if (configurationService.getEnvironment().equals(STAGING_ENVIRONMENT)) {
                    JWKSet publicJwkSet =
                            JWKSet.load(configurationService.getDocAppJwksUri().toURL());
                    var signingJWK =
                            publicJwkSet.getKeyByKeyId(
                                    configurationService.getDocAppSigningKeyID());
                    signingPublicKey = signingJWK.toPublicJWK().toECKey().toECPublicKey();
                } else {
                    signingPublicKey = configurationService.getDocAppCredentialSigningPublicKey();
                }
                JWSVerifier verifier = new ECDSAVerifier(signingPublicKey);
                return signed.verify(verifier);
            }
            throw new UnsuccesfulCredentialResponseException("CRI response is not signed");
        } catch (ParseException e) {
            throw new UnsuccesfulCredentialResponseException("Error parsing CRI response", e);
        } catch (JOSEException e) {
            throw new UnsuccesfulCredentialResponseException(
                    "Error verifying CRI response signature", e);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException | java.text.ParseException e) {
            LOG.error("Unable to load JWKSet", e);
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            LOG.error("Unable to get the Doc App JWKS URI", e);
            throw new RuntimeException(e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(configurationService.getDocAppTokenSigningKeyAlias())
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var messageToSign = ByteBuffer.wrap(message.getBytes());
            var signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(configurationService.getDocAppTokenSigningKeyAlias());
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
