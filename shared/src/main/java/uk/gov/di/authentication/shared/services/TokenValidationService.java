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
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

public class TokenValidationService {

    private final ConfigurationService configService;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidationService.class);

    public TokenValidationService(
            ConfigurationService configService, KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        LOGGER.info("Validating Access Token signature");
        return isTokenSignatureValid(accessToken.getValue());
    }

    public boolean validateRefreshTokenSignatureAndExpiry(RefreshToken refreshToken) {
        LOGGER.info("Validating Refresh Token signature");
        if (!isTokenSignatureValid(refreshToken.getValue())) {
            return false;
        }
        LOGGER.info("Validating Refresh Token expiry");
        if (hasTokenExpired(refreshToken.getValue())) {
            LOGGER.error("Refresh token has expired");
            return false;
        }
        return true;
    }

    private boolean hasTokenExpired(String tokenValue) {
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(tokenValue).getJWTClaimsSet();
            LocalDateTime localDateTime = LocalDateTime.now();
            Date currentDateTime = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
            if (!DateUtils.isAfter(claimsSet.getExpirationTime(), currentDateTime, 60)) {
                return true;
            }
        } catch (java.text.ParseException e) {
            LOGGER.error("Unable to parse token when checking if expired", e);
            return true;
        }
        return false;
    }

    public boolean isTokenSignatureValid(String tokenValue) {
        boolean isVerified;
        try {
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT signedJwt = SignedJWT.parse(tokenValue);
            JWSVerifier verifier = new ECDSAVerifier(getPublicJwk().toECKey());
            isVerified = signedJwt.verify(verifier);
        } catch (JOSEException | java.text.ParseException e) {
            LOGGER.error("Unable to validate Signature of Token", e);
            return false;
        }
        return isVerified;
    }

    public boolean validateRefreshTokenScopes(
            List<String> clientScopes, List<String> refreshTokenScopes) {
        if (!clientScopes.containsAll(refreshTokenScopes)) {
            LOGGER.error("Scopes in Client Registry does not contain all scopes in Refresh Token");
            return false;
        }
        if (!refreshTokenScopes.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            LOGGER.error("Scopes in Refresh Token does not contain OFFLINE_ACCESS scope");
            return false;
        }
        return true;
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
