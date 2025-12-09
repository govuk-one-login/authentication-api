package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.IncorrectKeyException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Optional;

import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsRsaDecrypterTest {

    @Mock private KmsConnectionService mockKmsConnectionService;

    @Mock private ConfigurationService mockConfigService;

    @InjectMocks private KmsRsaDecrypter kmsRsaDecrypter;

    private AutoCloseable mocks;

    private void stubKmsAliases() {
        when(mockConfigService.getAuthEncryptionKeyPrimaryAlias()).thenReturn("primaryKeyAlias");
        when(mockConfigService.getAuthEncryptionKeySecondaryAlias())
                .thenReturn(Optional.of("secondaryKeyAlias"));
    }

    @BeforeEach
    void setup() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void teardown() throws Exception {
        mocks.close();
    }

    @Test
    void decrypt_whenGivenNoEncryptedKey_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = null;
        Base64URL iv = new Base64URL("iv");
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = new Base64URL("authTag");
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                kmsRsaDecrypter.decrypt(
                                        header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("encrypted key"));
    }

    @Test
    void decrypt_whenGivenNoIv_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = new Base64URL("encryptedKey");
        Base64URL iv = null;
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = new Base64URL("authTag");
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                kmsRsaDecrypter.decrypt(
                                        header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("IV"));
    }

    @Test
    void decrypt_whenGivenNoAuthTag_shouldThrowAnException() {
        // Arrange
        JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
        Base64URL encryptedKey = new Base64URL("encryptedKey");
        Base64URL iv = new Base64URL("iv");
        Base64URL cypherText = new Base64URL("cypherText");
        Base64URL authTag = null;
        byte[] aad = new byte[] {};

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                kmsRsaDecrypter.decrypt(
                                        header, encryptedKey, iv, cypherText, authTag, aad),
                        "Expected decrypt() to throw, but it didn't");

        // Assert
        assertThat(thrown, instanceOf(JOSEException.class));
        assertThat(thrown.getMessage(), containsString("authentication tag"));
    }

    @Test
    void decrypt_whenPrimaryKeyWorks_shouldNotTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsConnectionService.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result =
                    kmsRsaDecrypter.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsConnectionService, times(1)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(result, equalTo(expectedResult));
        }
    }

    @Test
    void decrypt_whenPrimaryKeyIsWrong_shouldTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsConnectionService.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenThrow(IncorrectKeyException.builder().message("test").build());
            when(mockKmsConnectionService.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("secondary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result =
                    kmsRsaDecrypter.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsConnectionService, times(2)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(
                    decryptRequestCaptor.getAllValues().get(1).keyId(),
                    containsString("secondary"));
            assertThat(result, equalTo(expectedResult));
        }
    }

    @Test
    void decrypt_whenPrimaryKeyFails_shouldTrySecondaryKey() throws JOSEException {
        // Arrange
        stubKmsAliases();
        try (var staticMock = Mockito.mockStatic(ContentCryptoProvider.class)) {
            var expectedResult = new byte[] {};
            Mockito.when(
                            ContentCryptoProvider.decrypt(
                                    any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(expectedResult);
            JWEHeader header = new JWEHeader(RSA_OAEP_256, EncryptionMethod.A256GCM);
            Base64URL encryptedKey = new Base64URL("ZW5jcnlwdGVkS2V5");
            Base64URL iv = new Base64URL("iv");
            Base64URL cypherText = new Base64URL("cypherText");
            Base64URL authTag = new Base64URL("authTag");
            byte[] aad = new byte[] {};

            when(mockKmsConnectionService.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("primary"))))
                    .thenThrow(IncorrectKeyException.builder().message("test error").build());
            when(mockKmsConnectionService.decrypt(
                            argThat(
                                    (DecryptRequest dr) ->
                                            dr != null && dr.keyId().contains("secondary"))))
                    .thenReturn(
                            DecryptResponse.builder()
                                    .plaintext(SdkBytes.fromByteArray(new byte[] {1}))
                                    .build());

            // Act
            var result =
                    kmsRsaDecrypter.decrypt(header, encryptedKey, iv, cypherText, authTag, aad);

            // Assert
            ArgumentCaptor<DecryptRequest> decryptRequestCaptor =
                    ArgumentCaptor.forClass(DecryptRequest.class);
            verify(mockKmsConnectionService, times(2)).decrypt(decryptRequestCaptor.capture());
            assertThat(
                    decryptRequestCaptor.getAllValues().get(0).keyId(), containsString("primary"));
            assertThat(
                    decryptRequestCaptor.getAllValues().get(1).keyId(),
                    containsString("secondary"));
            assertThat(result, equalTo(expectedResult));
        }
    }
}
