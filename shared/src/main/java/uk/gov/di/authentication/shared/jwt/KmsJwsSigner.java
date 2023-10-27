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

public class KmsJwsSigner implements JWSSigner {

    private final KmsConnectionService kms;

    public KmsJwsSigner(KmsConnectionService kms) {
        this.kms = kms;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        return new Base64URL("");
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
