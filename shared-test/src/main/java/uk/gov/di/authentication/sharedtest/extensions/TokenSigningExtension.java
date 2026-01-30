package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import static com.nimbusds.jose.JWSAlgorithm.ES256;

public class TokenSigningExtension extends KmsKeyExtension {

    public TokenSigningExtension() {
        super("token-signing-key");
    }

    public TokenSigningExtension(String keyAliasSuffix) {
        super(keyAliasSuffix);
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        super.beforeAll(context);
    }

    public SignedJWT signJwt(JWTClaimsSet claimsSet, KeyPair keyPair) throws JOSEException {
        var jwsHeader = new JWSHeader(ES256);
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);

        var ecdsaSigner = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());

        signedJWT.sign(ecdsaSigner);
        return signedJWT;
    }
}
