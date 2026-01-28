package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

import java.net.URI;
import java.util.Optional;

public class KmsConnectionService {

    private final KmsClient kmsClient;
    private static final Logger LOG = LogManager.getLogger(KmsConnectionService.class);

    public KmsConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getLocalstackEndpointUri(),
                configurationService.getAwsRegion(),
                configurationService.getExternalTokenSigningKeyAlias(),
                configurationService.getNextExternalTokenSigningKeyAlias());
    }

    public KmsConnectionService(
            Optional<String> localstackEndpointUri,
            String awsRegion,
            String tokenSigningKeyId,
            String newTokenSigningKeyId) {
        if (localstackEndpointUri.isPresent()) {
            LOG.info("Localstack endpoint URI is present: {}", localstackEndpointUri.get());
            this.kmsClient =
                    KmsClient.builder()
                            .endpointOverride(URI.create(localstackEndpointUri.get()))
                            .credentialsProvider(DefaultCredentialsProvider.builder().build())
                            .region(Region.of(awsRegion))
                            .build();
        } else {
            this.kmsClient =
                    KmsClient.builder()
                            .region(Region.of(awsRegion))
                            .credentialsProvider(DefaultCredentialsProvider.builder().build())
                            .build();
        }
        warmUp(tokenSigningKeyId);
        warmUp(newTokenSigningKeyId);
    }

    public GetPublicKeyResponse getPublicKey(GetPublicKeyRequest getPublicKeyRequest) {
        LOG.info("Retrieving public key from KMS with KeyID {}", getPublicKeyRequest.keyId());
        return kmsClient.getPublicKey(getPublicKeyRequest);
    }

    public SignResponse sign(SignRequest signRequest) {
        LOG.info("Calling KMS with SignRequest and KeyId {}", signRequest.keyId());
        return kmsClient.sign(signRequest);
    }

    private void warmUp(String keyId) {
        GetPublicKeyRequest request = GetPublicKeyRequest.builder().keyId(keyId).build();
        try {
            kmsClient.getPublicKey(request);
        } catch (Exception e) {
            LOG.info("Unable to retrieve Public Key whilst warming up");
        }
    }
}
