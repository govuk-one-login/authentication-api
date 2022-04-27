package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterResult;
import com.amazonaws.services.simplesystemsmanagement.model.Parameter;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConfigurationServiceTest {

    @Test
    void sessionCookieMaxAgeShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals(3600, configurationService.getSessionCookieMaxAge());
    }

    @Test
    void getSessionCookieAttributesShouldEqualDefaultWhenEnvVarUnset() {
        ConfigurationService configurationService = new ConfigurationService();
        assertEquals("Secure; HttpOnly;", configurationService.getSessionCookieAttributes());
    }

    @Test
    void getDocAppCredentialSigningPublicKeyShouldGetECPublicKeyObjectFromParameterStorePEM()
            throws JOSEException {
        var privateKey = new ECKeyGenerator(Curve.P_256).keyID("my-key-id").generate();
        var publicKey = privateKey.toPublicJWK();
        var pem = publicKeyToPem(publicKey);
        var ssmClient = mock(AWSSimpleSystemsManagement.class);
        var request =
                new GetParameterRequest()
                        .withWithDecryption(true)
                        .withName("test-doc-app-public-signing-key");
        when(ssmClient.getParameter(eq(request)))
                .thenReturn(
                        new GetParameterResult()
                                .withParameter(
                                        new Parameter()
                                                .withName("test-doc-app-public-signing-key")
                                                .withValue(pem)));

        ConfigurationService configurationService = new ConfigurationService(ssmClient);

        var result = configurationService.getDocAppCredentialSigningPublicKey();

        assertThat(result, equalTo(publicKey.toECPublicKey(new BouncyCastleProvider())));
    }

    @Test
    void getDocAppCredentialSigningPublicKeyShouldThrowParameterStorePEMIsNull()
            throws JOSEException {
        var ssmClient = mock(AWSSimpleSystemsManagement.class);
        var request =
                new GetParameterRequest()
                        .withWithDecryption(true)
                        .withName("test-doc-app-public-signing-key");
        when(ssmClient.getParameter(eq(request)))
                .thenReturn(
                        new GetParameterResult()
                                .withParameter(
                                        new Parameter()
                                                .withName("test-doc-app-public-signing-key")
                                                .withValue("not-a-pem-public-key")));

        ConfigurationService configurationService = new ConfigurationService(ssmClient);

        assertThrows(
                RuntimeException.class,
                () -> configurationService.getDocAppCredentialSigningPublicKey());
    }

    private String publicKeyToPem(ECKey publicKey) {
        var writer = new StringWriter();
        try (var pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(
                    new PemObject("PUBLIC KEY", publicKey.toPublicKey().getEncoded()));

        } catch (IOException | JOSEException e) {
            throw new RuntimeException(e);
        }
        return writer.toString();
    }
}
