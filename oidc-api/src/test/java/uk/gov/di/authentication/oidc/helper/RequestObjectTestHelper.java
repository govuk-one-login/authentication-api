package uk.gov.di.authentication.oidc.helper;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;

import static uk.gov.di.authentication.sharedtest.helper.SupportedAlgorithmsTestHelper.getAlgorithmFamilyName;

public class RequestObjectTestHelper {

    public static SignedJWT generateSignedJWT(
            JWTClaimsSet jwtClaimsSet, KeyPair keyPair, JWSAlgorithm algorithm)
            throws JOSEException {
        String algorithmFamily = getAlgorithmFamilyName(algorithm);
        var jwsHeader = new JWSHeader(algorithm);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer =
                (algorithmFamily.equals("EC"))
                        ? new ECDSASigner(
                                keyPair.getPrivate(),
                                Curve.forJWSAlgorithm(algorithm).iterator().next())
                        : new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    public static SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws JOSEException {
        return generateSignedJWT(jwtClaimsSet, keyPair, JWSAlgorithm.RS256);
    }
}
