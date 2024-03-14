package uk.gov.di.authentication.shared.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Set;

import static com.nimbusds.jose.crypto.impl.ECDSA.getSignatureByteArrayLength;
import static com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToConcat;
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

        return header.getAlgorithm() == JWSAlgorithm.RS256
                ? signWithRsa(signingInput)
                : signWithEc(signingInput);
    }

    private Base64URL signWithRsa(byte[] signingInput) {
        var signedOutput = kms.sign(rsaSigningKeyId, RSASSA_PKCS1_V1_5_SHA_256, signingInput);

        return Base64URL.encode(signedOutput);
    }

    private Base64URL signWithEc(byte[] signingInput) throws JOSEException {
        var signedOutput = kms.sign(ecSigningKeyId, ECDSA_SHA_256, signingInput);

        return Base64URL.encode(
                transcodeSignatureToConcat(
                        signedOutput, getSignatureByteArrayLength(JWSAlgorithm.ES256)));
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256);
    }

    @Override
    public JCAContext getJCAContext() {
        return new JCAContext();
    }
}
