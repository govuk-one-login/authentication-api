package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.serialization.Json;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountDataApiServiceTest {
    private AutoCloseable closeable;

    @Mock private HttpClient httpClient;
    @Mock private ConfigurationService configurationService;

    private AccountDataApiService service;

    private static final String TOKEN = "token";
    private static final long TIMEOUT = 1000L;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        service = new AccountDataApiService(httpClient, configurationService);
        when(configurationService.getAccountDataURI()).thenReturn("https://example.com");
        when(configurationService.getAccountDataApiCallTimeout()).thenReturn(TIMEOUT);
    }

    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

    @Nested
    class RetrievePasskeysAsJson {
        @Test
        void shouldBuildCorrectRequestUri()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            when(httpClient.send(any(), any())).thenReturn(null);

            // Act
            service.retrievePasskeysAsJson("testPublicSubjectId", TOKEN);

            // Assert
            verify(httpClient).send(httpRequestCaptor.capture(), any());
            assertThat(
                    httpRequestCaptor.getValue().uri(),
                    equalTo(
                            URI.create(
                                    "https://example.com/accounts/testPublicSubjectId/authenticators/passkeys")));
            assertThat(httpRequestCaptor.getValue().method(), equalTo("GET"));
            assertThat(
                    httpRequestCaptor.getValue().headers().firstValue("Authorization").orElse(""),
                    equalTo("Bearer " + TOKEN));
        }

        @Test
        void shouldReturnVerbatimHttpResponse()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{'test': true}");
            when(httpClient.send(any(), any())).thenReturn(mockHttpResponse);

            // Act
            var resp = service.retrievePasskeysAsJson("testPublicSubjectId", TOKEN);

            // Assert
            assertThat(resp.statusCode(), equalTo(200));
            assertThat(resp.body(), equalTo("{'test': true}"));
        }
    }

    @Nested
    class RetrievePasskeys {
        @Test
        void shouldReturnDeserializedPasskeysResponse()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException,
                        Json.JsonException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            String validPasskeysJson =
                    """
                    {
                        "passkeys": [
                            {
                                "id": "credential-id-123",
                                "credential": "eyJhbGciOiJFUzI1NiJ9",
                                "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
                                "isAttested": true,
                                "signCount": 5,
                                "transports": ["internal", "hybrid"],
                                "isBackUpEligible": true,
                                "isBackedUp": false,
                                "createdAt": "2025-01-15T10:30:00",
                                "lastUsedAt": "2025-05-10T14:22:00"
                            },
                            {
                                "id": "credential-id-456",
                                "credential": "eyJhbGciOiJSUzI1NiJ9",
                                "aaguid": "adce0002-35bc-c60a-648b-0b25f1f05503",
                                "isAttested": false,
                                "signCount": 12,
                                "transports": ["usb"],
                                "isBackUpEligible": false,
                                "isBackedUp": false,
                                "createdAt": "2025-03-20T08:00:00",
                                "lastUsedAt": null
                            }
                        ]
                    }
                    """;
            when(mockHttpResponse.body()).thenReturn(validPasskeysJson);
            when(httpClient.send(any(), any())).thenReturn(mockHttpResponse);

            // Act
            var result = service.retrievePasskeys("testPublicSubjectId", TOKEN);

            // Assert
            assertThat(result.passkeys().size(), equalTo(2));
            assertThat(result.passkeys().get(0).passkeyId(), equalTo("credential-id-123"));
            assertThat(result.passkeys().get(0).signCount(), equalTo(5L));
            assertThat(result.passkeys().get(1).passkeyId(), equalTo("credential-id-456"));
            assertThat(result.passkeys().get(1).isAttested(), equalTo(false));
        }

        @Test
        void shouldNotAttemptToDeserialiseIfResponseStatusIsNot200()
                throws IOException, InterruptedException {
            var mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(404);
            String errorResponse =
                    """
                    {
                        "error": "this will not decode as a passkeys response"
                    """;
            when(mockHttpResponse.body()).thenReturn(errorResponse);
            when(httpClient.send(any(), any())).thenReturn(mockHttpResponse);

            assertThrows(
                    UnsuccessfulAccountDataApiResponseException.class,
                    () -> service.retrievePasskeys("testPublicSubjectId", TOKEN));
        }
    }

    @Nested
    class DeletePasskey {
        @Test
        void shouldBuildCorrectRequestUri()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            when(httpClient.send(any(), any())).thenReturn(null);

            // Act
            service.deletePasskey("testPublicSubjectId", "testPasskeyId", TOKEN);

            // Assert
            verify(httpClient).send(httpRequestCaptor.capture(), any());
            assertThat(
                    httpRequestCaptor.getValue().uri(),
                    equalTo(
                            URI.create(
                                    "https://example.com/accounts/testPublicSubjectId/authenticators/passkeys/testPasskeyId")));
            assertThat(httpRequestCaptor.getValue().method(), equalTo("DELETE"));
            assertThat(
                    httpRequestCaptor.getValue().headers().firstValue("Authorization").orElse(""),
                    equalTo("Bearer " + TOKEN));
        }

        @Test
        void shouldReturnVerbatimHttpResponse()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{'deleted': true}");
            when(httpClient.send(any(), any())).thenReturn(mockHttpResponse);

            // Act
            var resp = service.deletePasskey("testPublicSubjectId", "testPasskeyId", TOKEN);

            // Assert
            assertThat(resp.statusCode(), equalTo(200));
            assertThat(resp.body(), equalTo("{'deleted': true}"));
        }
    }

    @Nested
    class TimeoutRetry {
        @Test
        void shouldRetryOnceAfterTimeout()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var successResponse = mock(HttpResponse.class);
            when(successResponse.statusCode()).thenReturn(200);
            when(httpClient.send(any(), any()))
                    .thenThrow(new HttpTimeoutException("timed out"))
                    .thenReturn(successResponse);

            // Act
            var result = service.retrievePasskeysAsJson("sub", TOKEN);

            // Assert
            verify(httpClient, times(2)).send(any(), any());
            assertThat(result.statusCode(), equalTo(200));
        }

        @Test
        void shouldThrowAfterMaxRetriesExhausted() throws IOException, InterruptedException {
            // Arrange
            doThrow(new HttpTimeoutException("timed out")).when(httpClient).send(any(), any());

            // Act
            var exception =
                    assertThrows(
                            UnsuccessfulAccountDataApiResponseException.class,
                            () -> service.retrievePasskeysAsJson("sub", TOKEN));

            // Assert
            verify(httpClient, times(2)).send(any(), any());
            assertThat(exception.getMessage(), containsString("timeout of " + TIMEOUT));
        }

        @Test
        void shouldNotRetryOnSuccess()
                throws IOException,
                        InterruptedException,
                        UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var successResponse = mock(HttpResponse.class);
            when(successResponse.statusCode()).thenReturn(200);
            when(httpClient.send(any(), any())).thenReturn(successResponse);

            // Act
            service.retrievePasskeysAsJson("sub", TOKEN);

            // Assert
            verify(httpClient, times(1)).send(any(), any());
        }
    }

    @Nested
    class FailedRequest {
        @ParameterizedTest
        @EnumSource(PasskeysMethod.class)
        void shouldThrowWrappedExceptionIfHttpTimeoutExceptionEncountered(PasskeysMethod method)
                throws IOException, InterruptedException {
            // Arrange
            doThrow(new HttpTimeoutException("timed out")).when(httpClient).send(any(), any());

            // Act
            var exception =
                    assertThrows(
                            UnsuccessfulAccountDataApiResponseException.class,
                            () -> method.call(service));

            // Assert
            assertThat(exception.getMessage(), containsString("timeout of " + TIMEOUT));
            assertThat(exception.getCause(), instanceOf(HttpTimeoutException.class));
        }

        @ParameterizedTest
        @EnumSource(PasskeysMethod.class)
        void shouldThrowWrappedExceptionIfIOExceptionEncountered(PasskeysMethod method)
                throws IOException, InterruptedException {
            // Arrange
            doThrow(new IOException("connection failed")).when(httpClient).send(any(), any());

            // Act
            var exception =
                    assertThrows(
                            UnsuccessfulAccountDataApiResponseException.class,
                            () -> method.call(service));

            // Assert
            assertThat(exception.getMessage(), containsString("Error when attempting to call"));
            assertThat(exception.getCause(), instanceOf(IOException.class));
        }

        @ParameterizedTest
        @EnumSource(PasskeysMethod.class)
        void shouldThrowWrappedExceptionIfInterruptedExceptionEncountered(PasskeysMethod method)
                throws IOException, InterruptedException {
            // Arrange
            doThrow(new InterruptedException("interrupted")).when(httpClient).send(any(), any());

            // Act
            var exception =
                    assertThrows(
                            UnsuccessfulAccountDataApiResponseException.class,
                            () -> method.call(service));

            // Assert
            assertThat(exception.getMessage(), containsString("Interrupted exception"));
            assertThat(exception.getCause(), instanceOf(InterruptedException.class));
        }
    }

    enum PasskeysMethod {
        RETRIEVE_PASSKEYS,
        DELETE_PASSKEY;

        void call(AccountDataApiService service)
                throws UnsuccessfulAccountDataApiResponseException {
            switch (this) {
                case RETRIEVE_PASSKEYS -> service.retrievePasskeysAsJson(
                        "testPublicSubjectId", TOKEN);
                case DELETE_PASSKEY -> service.deletePasskey(
                        "testPublicSubjectId", "testPasskeyId", TOKEN);
            }
        }
    }
}
