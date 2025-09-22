package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class RsaKeyHelper {
    private static final Logger LOG = LogManager.getLogger(RsaKeyHelper.class);

    public static RSAPublicKey getRsaPublicKeyFromJwksCacheItem(JwksCacheItem jwksCacheItem) {
        try {
            LOG.info("Converting JwksCacheItem to RSAPublicKey");
            JWK publicEncryptionJwk = JWK.parse(jwksCacheItem.getKey());
            return new RSAKey.Builder((RSAKey) publicEncryptionJwk).build().toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error parsing the JwksCacheItem to JWK", e);
            throw new RuntimeException(e);
        }
    }
}
