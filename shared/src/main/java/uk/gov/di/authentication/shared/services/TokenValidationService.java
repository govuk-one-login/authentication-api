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
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
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
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidationService.class);

    public TokenValidationService(
            ConfigurationService configService, KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public boolean validateIdTokenSignature(String idTokenHint) {
        try {
            LOGGER.info("Validating ID token signature");
            SignedJWT idToken = SignedJWT.parse(idTokenHint);
            JWK publicJwk = getPublicJwk();
            JWKSet jwkSet = new JWKSet(publicJwk);
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
        LOGGER.info("Successfully validated ID token signature");
        return true;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        LOGGER.info("Validating Access Token signature");
        return validateTokenSignature(accessToken);
    }

    public boolean validateRefreshTokenSignature(RefreshToken refreshToken) {
        LOGGER.info("Validating Refresh Token signature");
        return validateTokenSignature(refreshToken);
    }

    private boolean validateTokenSignature(Token token) {
        boolean isVerified;
        try {
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT signedJwt = SignedJWT.parse(token.getValue());
            JWSVerifier verifier = new ECDSAVerifier(getPublicJwk().toECKey());
            isVerified = signedJwt.verify(verifier);
        } catch (JOSEException | java.text.ParseException e) {
            LOGGER.error("Unable to validate Signature of Token", e);
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
            return JWK.parse(jwk.toString());
        } catch (java.text.ParseException e) {
            LOGGER.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }
}
