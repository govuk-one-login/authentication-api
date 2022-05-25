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
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import uk.gov.di.authentication.shared.helpers.CryptoProviderHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class TokenValidationService {

    private final Map<String, ECKey> KEY_CACHE = new HashMap<>();
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
            Date currentDateTime = NowHelper.now();
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
        var jwk =
                segmentedFunctionCall(
                        "createJwk",
                        () ->
                                KEY_CACHE.computeIfAbsent(
                                        configService.getTokenSigningKeyAlias(), this::createJwk));

        return segmentedFunctionCall(
                "parseJwk",
                () -> {
                    try {
                        return JWK.parse(jwk.toString());
                    } catch (java.text.ParseException e) {
                        LOG.error("Error parsing the ECKey to JWK", e);
                        throw new RuntimeException(e);
                    }
                });
    }

    private ECKey createJwk(String keyId) {
        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest();
        getPublicKeyRequest.setKeyId(keyId);
        GetPublicKeyResult publicKeyResult = kmsConnectionService.getPublicKey(getPublicKeyRequest);

        PublicKey publicKey = createPublicKey(publicKeyResult);

        return new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                .keyID(hashSha256String(publicKeyResult.getKeyId()))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()))
                .build();
    }

    private PublicKey createPublicKey(GetPublicKeyResult publicKeyResult) {
        SubjectPublicKeyInfo subjectKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKeyResult.getPublicKey().array());

        try {
            return new JcaPEMKeyConverter()
                    .setProvider(CryptoProviderHelper.bouncyCastle())
                    .getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOG.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }
}
