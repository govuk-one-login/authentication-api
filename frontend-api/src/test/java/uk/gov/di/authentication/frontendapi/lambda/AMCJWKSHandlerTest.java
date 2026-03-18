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
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AMCJWKSHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JwksService jwksService = mock(JwksService.class);
    private final S3Client s3Client = mock(S3Client.class);

    private final ECKey authToAMCKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    private final ECKey authToAccountManagementKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();

    private AMCJWKSHandler handler;

    AMCJWKSHandlerTest() throws JOSEException {}

    @BeforeEach
    void setUp() {
        handler = new AMCJWKSHandler(jwksService, configurationService, s3Client);
        when(configurationService.getAMCJWKSBucketName()).thenReturn("amc-jwks-bucket");
        when(jwksService.getPublicAuthToAMCSigningJwkWithOpaqueId()).thenReturn(authToAMCKey);
        when(jwksService.getPublicAuthToAccountManagementSigningJwkWithOpaqueId())
                .thenReturn(authToAccountManagementKey);
    }

    @Test
    void shouldPutJwksToCorrectS3BucketAndKey() {
        handler.handleRequest(null, context);

        var requestCaptor = ArgumentCaptor.forClass(PutObjectRequest.class);
        verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));

        var putRequest = requestCaptor.getValue();
        assertEquals("amc-jwks-bucket", putRequest.bucket());
        assertEquals(".well-known/amc-jwks.json", putRequest.key());
        assertEquals("application/json", putRequest.contentType());
    }

    @Test
    void shouldPutBothKeysAsJwks() throws Exception {
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

        var expectedJwks = new JWKSet(List.of(authToAMCKey, authToAccountManagementKey));
        assertEquals(expectedJwks.toString(), actualJwks.toString());
    }
}
