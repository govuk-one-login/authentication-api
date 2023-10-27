package uk.gov.di.authentication.shared.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Collections;
import java.util.Set;

import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

public class KmsJwsSigner implements JWSSigner {

    private final KmsConnectionService kms;
    private final String rsaSigningKeyId;

    public KmsJwsSigner(KmsConnectionService kms, String rsaSigningKeyId) {
        this.kms = kms;
        this.rsaSigningKeyId = rsaSigningKeyId;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (signingInput.length == 0) {
            return new Base64URL("");
        }

        return Base64URL.encode(kms.sign(rsaSigningKeyId, RSASSA_PKCS1_V1_5_SHA_256, signingInput));
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Collections.emptySet();
    }

    @Override
    public JCAContext getJCAContext() {
        return new JCAContext();
    }
}
