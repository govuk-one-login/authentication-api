package uk.gov.di.authentication.shared.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class KmsJwsSignerTest {

    @Test
    void shouldReturnEmptyBaseUrlWithNoData() throws JOSEException {
        var signer = new KmsJwsSigner();
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        var emptyData = new byte[0];

        assertThat(signer.sign(header, emptyData), is(new Base64URL("")));
    }
}
