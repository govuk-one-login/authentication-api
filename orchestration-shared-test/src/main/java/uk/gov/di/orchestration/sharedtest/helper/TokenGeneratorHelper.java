package uk.gov.di.orchestration.sharedtest.helper;

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
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.sharedtest.exceptions.Unchecked;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class TokenGeneratorHelper {
    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey) {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        return generateIDToken(clientId, subject, issuerUrl, signingKey, null, expiryDate, null);
    }

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey, Date expiryDate) {
        return generateIDToken(clientId, subject, issuerUrl, signingKey, null, expiryDate, null);
    }

    public static SignedJWT generateIDToken(
            String clientId,
            Subject subject,
            String issuerUrl,
            String clientSessionId,
            JWK signingKey) {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        return generateIDToken(
                clientId, subject, issuerUrl, signingKey, clientSessionId, expiryDate, null);
    }

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, JWK signingKey, String vot) {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        return generateIDToken(clientId, subject, issuerUrl, signingKey, null, expiryDate, vot);
    }

    public static SignedJWT generateIDToken(
            String clientId,
            Subject subject,
            String issuerUrl,
            JWK signingKey,
            String clientSessionId,
            Date expiryDate,
            String vot) {
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(issuerUrl),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());
        if (Objects.nonNull(clientSessionId)) idTokenClaims.setClaim("sid", clientSessionId);
        if (Objects.nonNull(vot)) idTokenClaims.setClaim("vot", vot);

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

        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

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
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(UUID.randomUUID().toString());

        if (Objects.nonNull(identityClaims)) {
            claimsBuilder.claim(
                    "claims",
                    identityClaims.getUserInfoClaimsRequest().getEntries().stream()
                            .map(ClaimsSetRequest.Entry::getClaimName)
                            .toList());
        }

        JWSHeader jwsHeader =
                new JWSHeader.Builder(
                                signer instanceof RSASSASigner
                                        ? JWSAlgorithm.RS256
                                        : JWSAlgorithm.ES256)
                        .keyID(keyId)
                        .build();

        var signedJWT = new SignedJWT(jwsHeader, claimsBuilder.build());

        Unchecked.unchecked(signedJWT::sign).accept(signer);

        return signedJWT;
    }
}
