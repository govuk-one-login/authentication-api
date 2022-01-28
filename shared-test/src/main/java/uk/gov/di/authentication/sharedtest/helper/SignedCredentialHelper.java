package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SignedCredentialHelper {

    private SignedCredentialHelper() {}

    public static SignedJWT generateCredential() {
        try {
            ECKey ecSigningKey =
                    new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
            JWSSigner signer = new ECDSASigner(ecSigningKey);
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(ecSigningKey.getKeyID())
                            .build();
            var signedJWT = new SignedJWT(jwsHeader, new JWTClaimsSet.Builder().build());
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
