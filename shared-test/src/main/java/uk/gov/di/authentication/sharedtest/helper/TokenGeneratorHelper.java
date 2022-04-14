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
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

public class TokenGeneratorHelper {

    private static final String KEY_ID = "14342354354353";

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey) {
        LocalDateTime localDateTime = LocalDateTime.now().plus(2, ChronoUnit.MINUTES);
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

        LocalDateTime localDateTime = LocalDateTime.now().plus(2, ChronoUnit.MINUTES);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());

        return generateSignedToken(
                clientId, issuerUrl, scopes, signer, subject, keyId, expiryDate, null);
    }

    public static SignedJWT generateSignedToken(
            String clientId,
            String issuerUrl,
            List<String> scopes,
            JWSSigner signer,
            Subject subject,
            String keyId,
            Date expiryDate) {

        return generateSignedToken(
                clientId, issuerUrl, scopes, signer, subject, keyId, expiryDate, null);
    }

    public static SignedJWT generateSignedToken(
            String clientId,
            String issuerUrl,
            List<String> scopes,
            JWSSigner signer,
            Subject subject,
            String keyId,
            Date expiryDate,
            OIDCClaimsRequest identityClaims) {

        JWTClaimsSet.Builder claimsBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(issuerUrl)
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()))
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(UUID.randomUUID().toString());

        if (Objects.nonNull(identityClaims)) {
            claimsBuilder.claim(
                    "claims",
                    identityClaims.getUserInfoClaimsRequest().getEntries().stream()
                            .map(ClaimsSetRequest.Entry::getClaimName)
                            .collect(Collectors.toList()));
        }

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();

        var signedJWT = new SignedJWT(jwsHeader, claimsBuilder.build());

        unchecked(signedJWT::sign).accept(signer);

        return signedJWT;
    }
}
