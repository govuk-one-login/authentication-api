package uk.gov.di.authentication.shared.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Collections;
import java.util.Set;

import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.ECDSA_SHA_256;
import static software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;

public class KmsJwsSigner implements JWSSigner {

    private final KmsConnectionService kms;
    private final String rsaSigningKeyId;
    private final String ecSigningKeyId;

    public KmsJwsSigner(KmsConnectionService kms, String rsaSigningKeyId, String ecSigningKeyId) {
        this.kms = kms;
        this.rsaSigningKeyId = rsaSigningKeyId;
        this.ecSigningKeyId = ecSigningKeyId;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (signingInput.length == 0) {
            return new Base64URL("");
        }

        var signingKey =
                header.getAlgorithm() == JWSAlgorithm.RS256 ? rsaSigningKeyId : ecSigningKeyId;

        var signingAlgorithm =
                header.getAlgorithm() == JWSAlgorithm.RS256
                        ? RSASSA_PKCS1_V1_5_SHA_256
                        : ECDSA_SHA_256;

        var signedOutput = kms.sign(signingKey, signingAlgorithm, signingInput);

        if (header.getAlgorithm() == JWSAlgorithm.RS256) {
            return Base64URL.encode(signedOutput);
        } else {
            return Base64URL.encode(
                    ECDSA.transcodeSignatureToConcat(
                            signedOutput, ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)));
        }
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
