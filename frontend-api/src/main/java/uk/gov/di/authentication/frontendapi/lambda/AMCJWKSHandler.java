package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.net.URI;
import java.util.List;

public class AMCJWKSHandler implements RequestHandler<Object, Void> {
    private final ConfigurationService configurationService;
    private final JwksService jwksService;
    private final S3Client s3Client;

    public AMCJWKSHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCJWKSHandler(
            JwksService jwksService, ConfigurationService configurationService, S3Client s3Client) {
        this.configurationService = configurationService;
        this.jwksService = jwksService;
        this.s3Client = s3Client;
    }

    public AMCJWKSHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        var kmsConnectionService = new KmsConnectionService(configurationService);
        this.jwksService = new JwksService(configurationService, kmsConnectionService);
        this.s3Client =
                configurationService
                        .getLocalstackEndpointUri()
                        .map(
                                endpoint ->
                                        S3Client.builder()
                                                .endpointOverride(URI.create(endpoint))
                                                .region(
                                                        Region.of(
                                                                configurationService
                                                                        .getAwsRegion()))
                                                .credentialsProvider(
                                                        StaticCredentialsProvider.create(
                                                                AwsBasicCredentials.create(
                                                                        "FAKEACCESSKEY",
                                                                        "FAKESECRETKEY")))
                                                .serviceConfiguration(
                                                        S3Configuration.builder()
                                                                .pathStyleAccessEnabled(true)
                                                                .build())
                                                .build())
                        .orElseGet(
                                () ->
                                        S3Client.builder()
                                                .credentialsProvider(
                                                        DefaultCredentialsProvider.builder()
                                                                .build())
                                                .region(
                                                        Region.of(
                                                                configurationService
                                                                        .getAwsRegion()))
                                                .build());
    }

    @Override
    public Void handleRequest(Object event, Context context) {
        JWK authToAMCJwk = jwksService.getPublicAuthToAMCSigningJwkWithOpaqueId();
        JWK authToAccountManagementJwk =
                jwksService.getPublicAuthToAccountManagementSigningJwkWithOpaqueId();

        var jwks = new JWKSet(List.of(authToAMCJwk, authToAccountManagementJwk)).toString(true);

        s3Client.putObject(
                PutObjectRequest.builder()
                        .bucket(configurationService.getAMCJWKSBucketName())
                        .key(".well-known/amc-jwks.json")
                        .contentType("application/json")
                        .build(),
                RequestBody.fromString(jwks));

        return null;
    }
}
