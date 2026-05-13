package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

public class TokenGeneratorHelper {

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
                            .collect(Collectors.toList()));
        }

        JWSHeader jwsHeader =
                new JWSHeader.Builder(
                                signer instanceof RSASSASigner
                                        ? JWSAlgorithm.RS256
                                        : JWSAlgorithm.ES256)
                        .keyID(keyId)
                        .build();

        var signedJWT = new SignedJWT(jwsHeader, claimsBuilder.build());

        unchecked(signedJWT::sign).accept(signer);

        return signedJWT;
    }
}
