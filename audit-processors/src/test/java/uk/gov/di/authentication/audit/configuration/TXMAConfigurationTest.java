package uk.gov.di.authentication.audit.configuration;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TXMAConfigurationTest {

    private final SecretsManagerClient secretsManagerClient = mock(SecretsManagerClient.class);
    private TXMAConfiguration txmaConfiguration = new TXMAConfiguration(secretsManagerClient);

    @Test
    void returnsHmacSecretWhenArnProvidedAndSubsequentRequestShouldNotCallSecretsManager() {
        var config = spy(txmaConfiguration);
        var result = GetSecretValueResponse.builder().secretString("a-valid-hmac-key").build();
        doReturn(Optional.of("a-valid-arn")).when(config).getObfuscationHMACSecretArn();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                .thenReturn(result);

        var hmac = config.getObfuscationHMACSecret();

        assertThat(hmac.get(), equalTo("a-valid-hmac-key"));
        verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));

        hmac = config.getObfuscationHMACSecret();

        assertThat(hmac.get(), equalTo("a-valid-hmac-key"));
        verify(secretsManagerClient, times(1)).getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void returnsEmptySecretWhenNoArnProvided() {
        var config = spy(txmaConfiguration);
        var result = GetSecretValueResponse.builder().secretString("a-valid-hmac-key").build();
        doReturn(Optional.empty()).when(config).getObfuscationHMACSecretArn();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                .thenReturn(result);

        var hmac = config.getObfuscationHMACSecret();

        assertThat(hmac, equalTo(Optional.empty()));
    }

    @Test
    void returnsEmptySecretWhenExceptionOccurs() {
        var config = spy(txmaConfiguration);
        var result = GetSecretValueResponse.builder().secretString("a-valid-hmac-key").build();
        doReturn(Optional.of("a-valid-arn")).when(config).getObfuscationHMACSecretArn();
        when(secretsManagerClient.getSecretValue(any(GetSecretValueRequest.class)))
                .thenThrow(ResourceNotFoundException.class);

        var hmac = config.getObfuscationHMACSecret();

        assertThat(hmac, equalTo(Optional.empty()));
    }
}
