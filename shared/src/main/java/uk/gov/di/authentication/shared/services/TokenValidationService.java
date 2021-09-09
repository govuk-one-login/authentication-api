package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

public class TokenValidationService {

    private final ConfigurationService configService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidationService.class);

    public TokenValidationService(
            ConfigurationService configService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public boolean validateIdTokenSignature(String idTokenHint) {
        try {
            LOGGER.info("Validating ID token signature");
            LOGGER.info("IDTokenHint: " + idTokenHint);
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT idToken = SignedJWT.parse(idTokenHint);
            LOGGER.info("ClientID:" + idToken.getJWTClaimsSet().getAudience().get(0));
            LOGGER.info("Issuer: " + configService.getBaseURL().get());
            JWK publicJwk = getPublicJwk();
            LOGGER.info("PublicJWK: " + publicJwk.toString());
            JWKSet jwkSet = new JWKSet(publicJwk);
            LOGGER.info("JWKSET: " + jwkSet);
            IDTokenValidator validator =
                    new IDTokenValidator(
                            new Issuer(configService.getBaseURL().get()),
                            new ClientID(idToken.getJWTClaimsSet().getAudience().get(0)),
                            JWSAlgorithm.ES256,
                            jwkSet);
            JWSKeySelector jwsKeySelector = validator.getJWSKeySelector();
            LOGGER.info("KEYSELECTOR: " + jwsKeySelector.selectJWSKeys(idToken.getHeader(), null));
            validator.validate(idToken, null);
        } catch (java.text.ParseException | JOSEException | BadJOSEException e) {
            LOGGER.error("Unable to validate Signature of ID token", e);
            return false;
        }
        return true;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        boolean isVerified;
        try {
            LOGGER.info("Validating Access Token signature");
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT signedJwt = SignedJWT.parse(accessToken.getValue());
            JWSVerifier verifier = new ECDSAVerifier(getPublicJwk().toECKey());
            isVerified = signedJwt.verify(verifier);
        } catch (JOSEException | java.text.ParseException e) {
            LOGGER.error("Unable to validate Signature of Access token", e);
            return false;
        }
        return isVerified;
    }

    public PublicKey getPublicKey() {
        LOGGER.info("Creating GetPublicKeyRequest to retrieve PublicKey from KMS");
        Provider bcProvider = new BouncyCastleProvider();
        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest();
        getPublicKeyRequest.setKeyId(configService.getTokenSigningKeyAlias());
        GetPublicKeyResult publicKeyResult = kmsConnectionService.getPublicKey(getPublicKeyRequest);
        try {
            LOGGER.info("PUBLICKEYRESULT: " + publicKeyResult.toString());
            SubjectPublicKeyInfo subjectKeyInfo =
                    SubjectPublicKeyInfo.getInstance(publicKeyResult.getPublicKey().array());
            return new JcaPEMKeyConverter().setProvider(bcProvider).getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOGGER.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }

    public JWK getPublicJwk() {
        try {
            PublicKey publicKey = getPublicKey();
            ECKey jwk =
                    new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                            .keyID(configService.getTokenSigningKeyAlias())
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()))
                            .build();
            LOGGER.info("ECKey: " + jwk.toJSONString());
            LOGGER.info("ECKey KeyID: " + jwk.getKeyID());
            return JWK.parse(jwk.toJSONObject());
        } catch (java.text.ParseException e) {
            LOGGER.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }
}
