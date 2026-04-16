package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import static uk.gov.di.authentication.frontendapi.helpers.S3ClientHelper.createDefaultS3Client;
import static uk.gov.di.authentication.frontendapi.helpers.S3ClientHelper.createLocalstackS3Client;

public class ADJWKSHandler implements RequestHandler<Object, Void> {
    private final ConfigurationService configurationService;
    private final JwksService jwksService;
    private final S3Client s3Client;
    private static final Logger LOG = LogManager.getLogger(ADJWKSHandler.class);

    public ADJWKSHandler() {
        this(ConfigurationService.getInstance());
    }

    public ADJWKSHandler(
            JwksService jwksService, ConfigurationService configurationService, S3Client s3Client) {
        this.configurationService = configurationService;
        this.jwksService = jwksService;
        this.s3Client = s3Client;
    }

    public ADJWKSHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.jwksService = new JwksService(configurationService, kmsConnectionService);
        this.s3Client =
                configurationService
                        .getLocalstackEndpointUri()
                        .map(endpoint -> createLocalstackS3Client(configurationService, endpoint))
                        .orElseGet(() -> createDefaultS3Client(configurationService));
    }

    @Override
    public Void handleRequest(Object event, Context context) {
        LOG.info("AD JWKS lambda invoked");
        JWK authToADSigningJwk = jwksService.getPublicAuthToAccountDataSigningJwkWithOpaqueId();

        var jwks = new JWKSet(authToADSigningJwk).toString(true);

        s3Client.putObject(
                PutObjectRequest.builder()
                        .bucket(configurationService.getADJWKSBucketName())
                        .key(".well-known/ad-jwks.json")
                        .contentType("application/json")
                        .build(),
                RequestBody.fromString(jwks));

        LOG.info("AD JWKS has been put to S3");
        return null;
    }
}
