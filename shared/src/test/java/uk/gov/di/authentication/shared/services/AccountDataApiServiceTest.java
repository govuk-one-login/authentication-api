package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
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
    class RetrievePasskeys {
        @Nested
        class SuccessfulRequest {
            @Test
            void shouldBuildCorrectRequestUri()
                    throws IOException,
                            InterruptedException,
                            UnsuccessfulAccountDataApiResponseException {
                // Arrange
                var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
                when(httpClient.send(any(), any())).thenReturn(null);

                // Act
                service.retrievePasskeys("testPublicSubjectId", TOKEN);

                // Assert
                verify(httpClient).send(httpRequestCaptor.capture(), any());
                assertThat(
                        httpRequestCaptor.getValue().uri(),
                        equalTo(
                                URI.create(
                                        "https://example.com/accounts/testPublicSubjectId/authenticators/passkeys")));
                assertThat(httpRequestCaptor.getValue().method(), equalTo("GET"));
                assertThat(
                        httpRequestCaptor
                                .getValue()
                                .headers()
                                .firstValue("Authorization")
                                .orElse(""),
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
                var resp = service.retrievePasskeys("testPublicSubjectId", TOKEN);

                // Assert
                assertThat(resp.statusCode(), equalTo(200));
                assertThat(resp.body(), equalTo("{'test': true}"));
            }
        }

        @Nested
        class FailedRequest {
            @Test
            void shouldThrowWrappedExceptionIfHttpTimeoutExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new java.net.http.HttpTimeoutException("timed out"))
                        .when(httpClient)
                        .send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () -> service.retrievePasskeys("testPublicSubjectId", TOKEN));
                assertThat(exception.getMessage(), containsString("timeout of " + TIMEOUT));
                assertThat(
                        exception.getCause(), instanceOf(java.net.http.HttpTimeoutException.class));
            }

            @Test
            void shouldThrowWrappedExceptionIfIOExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new IOException("connection failed")).when(httpClient).send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () -> service.retrievePasskeys("testPublicSubjectId", TOKEN));
                assertThat(exception.getMessage(), containsString("Error when attempting to call"));
                assertThat(exception.getCause(), instanceOf(IOException.class));
            }

            @Test
            void shouldThrowWrappedExceptionIfInterruptedExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new InterruptedException("interrupted"))
                        .when(httpClient)
                        .send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () -> service.retrievePasskeys("testPublicSubjectId", TOKEN));
                assertThat(exception.getMessage(), containsString("Interrupted exception"));
                assertThat(exception.getCause(), instanceOf(InterruptedException.class));
            }
        }
    }

    @Nested
    class DeletePasskey {
        @Nested
        class SuccessfulRequest {
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
                        httpRequestCaptor
                                .getValue()
                                .headers()
                                .firstValue("Authorization")
                                .orElse(""),
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
        class FailedRequest {
            @Test
            void shouldThrowWrappedExceptionIfHttpTimeoutExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new java.net.http.HttpTimeoutException("timed out"))
                        .when(httpClient)
                        .send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () ->
                                        service.deletePasskey(
                                                "testPublicSubjectId", "testPasskeyId", TOKEN));
                assertThat(exception.getMessage(), containsString("timeout of " + TIMEOUT));
                assertThat(
                        exception.getCause(), instanceOf(java.net.http.HttpTimeoutException.class));
            }

            @Test
            void shouldThrowWrappedExceptionIfIOExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new IOException("connection failed")).when(httpClient).send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () ->
                                        service.deletePasskey(
                                                "testPublicSubjectId", "testPasskeyId", TOKEN));
                assertThat(exception.getMessage(), containsString("Error when attempting to call"));
                assertThat(exception.getCause(), instanceOf(IOException.class));
            }

            @Test
            void shouldThrowWrappedExceptionIfInterruptedExceptionEncountered()
                    throws IOException, InterruptedException {
                // Arrange
                doThrow(new InterruptedException("interrupted"))
                        .when(httpClient)
                        .send(any(), any());

                // Act & Assert
                var exception =
                        assertThrows(
                                UnsuccessfulAccountDataApiResponseException.class,
                                () ->
                                        service.deletePasskey(
                                                "testPublicSubjectId", "testPasskeyId", TOKEN));
                assertThat(exception.getMessage(), containsString("Interrupted exception"));
                assertThat(exception.getCause(), instanceOf(InterruptedException.class));
            }
        }
    }
}
