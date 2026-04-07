package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ADJWKSHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JwksService jwksService = mock(JwksService.class);
    private final S3Client s3Client = mock(S3Client.class);

    private final ECKey authToADKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();

    private ADJWKSHandler handler;

    public ADJWKSHandlerTest() throws JOSEException {}

    @BeforeEach
    void setUp() {
        handler = new ADJWKSHandler(jwksService, configurationService, s3Client);
        when(configurationService.getADJWKSBucketName()).thenReturn("ad-jwks-bucket");
        when(jwksService.getPublicAuthToAccountDataSigningJwkWithOpaqueId())
                .thenReturn(authToADKey);
    }

    @Test
    void shouldPutJwksToCorrectS3BucketAndKey() {
        handler.handleRequest(null, context);

        var requestCaptor = ArgumentCaptor.forClass(PutObjectRequest.class);
        verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));

        var putRequest = requestCaptor.getValue();
        assertEquals("ad-jwks-bucket", putRequest.bucket());
        assertEquals(".well-known/ad-jwks.json", putRequest.key());
        assertEquals("application/json", putRequest.contentType());
    }

    @Test
    void shouldPutADKeyAsJwks() throws Exception {
        handler.handleRequest(null, context);

        var bodyCaptor = ArgumentCaptor.forClass(RequestBody.class);
        verify(s3Client).putObject(any(PutObjectRequest.class), bodyCaptor.capture());

        var actualJwks =
                JWKSet.parse(
                        new String(
                                bodyCaptor
                                        .getValue()
                                        .contentStreamProvider()
                                        .newStream()
                                        .readAllBytes(),
                                StandardCharsets.UTF_8));

        var expectedJwks = new JWKSet(authToADKey);
        assertEquals(expectedJwks.toString(), actualJwks.toString());
    }
}
