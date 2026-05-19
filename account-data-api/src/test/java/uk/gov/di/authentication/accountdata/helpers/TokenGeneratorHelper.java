package uk.gov.di.authentication.accountdata.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Date;
import java.util.UUID;

public class TokenGeneratorHelper {
    public static JWTClaimsSet.Builder claimsSetBuilderWithoutSubject(Date expiryDate) {
        return new JWTClaimsSet.Builder()
                .claim("scope", "passkey-retrieve")
                .issuer("https://example.com")
                .audience("https://account-data.example.com")
                .expirationTime(expiryDate)
                .issueTime(NowHelper.now())
                .notBeforeTime(NowHelper.now())
                .claim("client_id", "some-client-id")
                .jwtID(UUID.randomUUID().toString());
    }

    public static JWTClaimsSet.Builder claimsSetBuilder(String subject, Date expiryDate) {
        return claimsSetBuilderWithoutSubject(expiryDate).subject(subject);
    }

    public static SignedJWT generateSignedToken(
            JWSSigner signer, String keyId, JWTClaimsSet.Builder claimsBuilder) {

        var algorithm = signer instanceof RSASSASigner ? JWSAlgorithm.RS256 : JWSAlgorithm.ES256;
        var jwsHeader = new JWSHeader.Builder(algorithm).keyID(keyId).build();
        var signedJWT = new SignedJWT(jwsHeader, claimsBuilder.build());

        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT;
    }
}
