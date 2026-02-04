package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

public class JwtHelper {
    private JwtHelper() {}

    public static String jsonToSignedJwt(String jsonString, ECKey ecKey)
            throws JOSEException, ParseException {
        JWSSigner signer = new ECDSASigner(ecKey.toECPrivateKey());
        return jsonToSignedJwt(jsonString, signer, JWSAlgorithm.ES256, ecKey.getKeyID());
    }

    public static String jsonToSignedJwt(
            String jsonString, JWSSigner signer, JWSAlgorithm algorithm, String keyId)
            throws ParseException, JOSEException {
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonString);
        JWSHeader header = new JWSHeader.Builder(algorithm).keyID(keyId).build();
        SignedJWT jwt = new SignedJWT(header, claimsSet);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
