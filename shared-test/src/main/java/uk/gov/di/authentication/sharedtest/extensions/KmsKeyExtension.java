package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.CreateAliasRequest;
import com.amazonaws.services.kms.model.CreateKeyRequest;
import com.amazonaws.services.kms.model.DescribeKeyRequest;
import com.amazonaws.services.kms.model.KeySpec;
import com.amazonaws.services.kms.model.NotFoundException;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.Optional;

public class KmsKeyExtension implements BeforeAllCallback {

    private static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    private static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");
    private static final String TOKEN_SIGNING_KEY_ALIAS =
            System.getenv().get("TOKEN_SIGNING_KEY_ALIAS");

    private final KmsConnectionService kmsConnectionService =
            new KmsConnectionService(
                    Optional.of(LOCALSTACK_ENDPOINT), REGION, TOKEN_SIGNING_KEY_ALIAS);

    private AWSKMS kms;

    public SignedJWT signIdToken(JWTClaimsSet claimsSet) {
        try {
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(TOKEN_SIGNING_KEY_ALIAS)
                            .build();
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignRequest signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(TOKEN_SIGNING_KEY_ALIAS);
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsConnectionService.sign(signRequest);
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public SignedJWT signAccessToken(JWTClaimsSet claimsSet) {
        try {
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(TOKEN_SIGNING_KEY_ALIAS)
                            .build();
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignRequest signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(TOKEN_SIGNING_KEY_ALIAS);
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsConnectionService.sign(signRequest);
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        kms =
                AWSKMSClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();

        if (!keyExists(TOKEN_SIGNING_KEY_ALIAS)) {
            createTokenSigningKey(TOKEN_SIGNING_KEY_ALIAS);
        }
    }

    private void createTokenSigningKey(String keyAlias) {
        CreateKeyRequest keyRequest =
                new CreateKeyRequest()
                        .withKeySpec(KeySpec.ECC_NIST_P256)
                        .withKeyUsage("SIGN_VERIFY");

        var keyResponse = kms.createKey(keyRequest);

        CreateAliasRequest aliasRequest =
                new CreateAliasRequest()
                        .withAliasName(keyAlias)
                        .withTargetKeyId(keyResponse.getKeyMetadata().getKeyId());

        kms.createAlias(aliasRequest);
    }

    private boolean keyExists(String keyAlias) {
        try {
            var request = new DescribeKeyRequest().withKeyId(keyAlias);
            kms.describeKey(request);
            return true;
        } catch (NotFoundException ignored) {
            return false;
        }
    }
}
