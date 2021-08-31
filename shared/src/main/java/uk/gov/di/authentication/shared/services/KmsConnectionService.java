package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class KmsConnectionService {

    private final AWSKMS kmsClient;
    private static final Logger LOGGER = LoggerFactory.getLogger(KmsConnectionService.class);

    public KmsConnectionService(ConfigurationService configurationService) {
        this(configurationService.getLocalstackEndpointUri(), configurationService.getAwsRegion());
    }

    public KmsConnectionService(Optional<String> localstackEndpointUri, String awsRegion) {
        if (localstackEndpointUri.isPresent()) {
            LOGGER.info("Localstack endpoint URI is present: " + localstackEndpointUri.get());
            this.kmsClient =
                    AWSKMSClientBuilder.standard()
                            .withEndpointConfiguration(
                                    new AwsClientBuilder.EndpointConfiguration(
                                            localstackEndpointUri.get(), awsRegion))
                            .build();
        } else {
            this.kmsClient = AWSKMSClientBuilder.standard().withRegion(awsRegion).build();
        }
        warmUp();
    }

    public GetPublicKeyResult getPublicKey(GetPublicKeyRequest getPublicKeyRequest) {
        LOGGER.info("Retrieving public key from KMS with KeyID {}", getPublicKeyRequest.getKeyId());
        return kmsClient.getPublicKey(getPublicKeyRequest);
    }

    public SignResult sign(SignRequest signRequest) {
        LOGGER.info("Calling KMS with SignRequest and KeyId {}", signRequest.getKeyId());
        return kmsClient.sign(signRequest);
    }

    private void warmUp() {
        kmsClient.listKeys();
    }
}
