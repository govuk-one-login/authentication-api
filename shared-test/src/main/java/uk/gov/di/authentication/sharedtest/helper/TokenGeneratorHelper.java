package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class TokenGeneratorHelper {

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        return generateIDToken(clientId, subject, issuerUrl, signingKey, expiryDate);
    }

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey, Date expiryDate) {
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(issuerUrl),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());
        try {
            JWSSigner signer;
            JWSHeader.Builder jwsHeaderBuilder;
            if (signingKey instanceof RSAKey) {
                signer = new RSASSASigner(signingKey.toRSAKey());
                jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.RS512);
            } else if (signingKey instanceof ECKey) {
                signer = new ECDSASigner(signingKey.toECKey());
                jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256);
            } else {
                throw new RuntimeException("Invalid JWKKey");
            }
            var signedJWT =
                    new SignedJWT(
                            jwsHeaderBuilder.keyID(signingKey.getKeyID()).build(),
                            idTokenClaims.toJWTClaimsSet());
            signedJWT.sign(signer);
            return signedJWT;

        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static SignedJWT generateSignedToken(
            String clientId,
            String issuerUrl,
            List<String> scopes,
            JWSSigner signer,
            Subject subject,
            String keyId) {

        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());

        return generateSignedToken(clientId, issuerUrl, scopes, signer, subject, keyId, expiryDate);
    }

    public static SignedJWT generateSignedToken(
            String clientId,
            String issuerUrl,
            List<String> scopes,
            JWSSigner signer,
            Subject subject,
            String keyId,
            Date expiryDate) {

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(issuerUrl)
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()))
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();
        try {
            var signedJWT = new SignedJWT(jwsHeader, claimsSet);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
