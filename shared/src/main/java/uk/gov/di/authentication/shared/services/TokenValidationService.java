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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class TokenValidationService {

    private final ConfigurationService configService;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOG = LogManager.getLogger(TokenValidationService.class);

    public TokenValidationService(
            ConfigurationService configService, KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        return isTokenSignatureValid(accessToken.getValue());
    }

    public boolean validateRefreshTokenSignatureAndExpiry(RefreshToken refreshToken) {
        if (!isTokenSignatureValid(refreshToken.getValue())) {
            LOG.warn("Refresh token has invalid signature");
            return false;
        }
        if (hasTokenExpired(refreshToken.getValue())) {
            LOG.warn("Refresh token has expired");
            return false;
        }
        return true;
    }

    private boolean hasTokenExpired(String tokenValue) {
        try {
            JWTClaimsSet claimsSet = SignedJWT.parse(tokenValue).getJWTClaimsSet();
            LocalDateTime localDateTime = LocalDateTime.now();
            Date currentDateTime = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
            if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
                return true;
            }
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse token when checking if expired", e);
            return true;
        }
        return false;
    }

    public boolean isTokenSignatureValid(String tokenValue) {
        try {
            JWSVerifier verifier = new ECDSAVerifier(getPublicJwkWithOpaqueId().toECKey());

            return SignedJWT.parse(tokenValue).verify(verifier);
        } catch (JOSEException | java.text.ParseException e) {
            LOG.warn("Unable to validate Signature of Token", e);
            return false;
        }
    }

    public boolean validateRefreshTokenScopes(
            List<String> clientScopes, List<String> refreshTokenScopes) {
        if (!clientScopes.containsAll(refreshTokenScopes)) {
            LOG.warn("Scopes in Client Registry does not contain all scopes in Refresh Token");
            return false;
        }
        if (!refreshTokenScopes.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            LOG.warn("Scopes in Refresh Token does not contain OFFLINE_ACCESS scope");
            return false;
        }
        return true;
    }

    public JWK getPublicJwkWithOpaqueId() {
        try {
            return JWK.parse(createJwk().build().toString());
        } catch (java.text.ParseException e) {
            LOG.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }

    @Deprecated
    public JWK getPublicJwkWithAlias() {
        try {
            return JWK.parse(
                    createJwk().keyID(configService.getTokenSigningKeyAlias()).build().toString());
        } catch (java.text.ParseException e) {
            LOG.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }

    private ECKey.Builder createJwk() {
        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest();
        getPublicKeyRequest.setKeyId(configService.getTokenSigningKeyAlias());
        GetPublicKeyResult publicKeyResult = kmsConnectionService.getPublicKey(getPublicKeyRequest);

        PublicKey publicKey = createPublicKey(publicKeyResult);

        return new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                .keyID(hashSha256String(publicKeyResult.getKeyId()))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()));
    }

    private PublicKey createPublicKey(GetPublicKeyResult publicKeyResult) {
        SubjectPublicKeyInfo subjectKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKeyResult.getPublicKey().array());

        try {
            return new JcaPEMKeyConverter()
                    .setProvider(new BouncyCastleProvider())
                    .getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOG.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }
}
