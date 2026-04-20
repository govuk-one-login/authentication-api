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
import java.util.List;
import java.util.UUID;

public class TokenGeneratorHelper {

    public static SignedJWT generateSignedToken(
            JWSSigner signer, String keyId, Date expiryDate, String subject) {

        JWTClaimsSet.Builder claimsBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", List.of("some-scopes"))
                        .issuer("https://example.com")
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", "some-client-id")
                        .subject(subject)
                        .jwtID(UUID.randomUUID().toString());

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
