package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.HttpClientHelper;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.interruptedException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.ioException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.timeoutException;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class AccountDataApiService {
    private static final Logger LOG = LogManager.getLogger(AccountDataApiService.class);
    private static final int MAX_TRIES = 2;
    private final HttpClient httpClient;
    private final ConfigurationService configurationService;

    public AccountDataApiService(ConfigurationService configurationService) {
        this(HttpClientHelper.newInstrumentedHttpClient(), configurationService);
    }

    public AccountDataApiService(HttpClient httpClient, ConfigurationService configurationService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
    }

    public HttpResponse<String> retrievePasskeys(String publicSubjectId, String token)
            throws UnsuccessfulAccountDataApiResponseException {
        var request =
                HttpRequest.newBuilder(
                                buildURI(
                                        configurationService.getAccountDataURI(),
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys"))
                        .header("Authorization", "Bearer " + token)
                        .GET()
                        .timeout(
                                Duration.ofMillis(
                                        configurationService.getAccountDataApiCallTimeout()))
                        .build();
        return sendRequest(request);
    }

    public HttpResponse<String> deletePasskey(
            String publicSubjectId, String passkeyId, String token)
            throws UnsuccessfulAccountDataApiResponseException {
        var request =
                HttpRequest.newBuilder(
                                buildURI(
                                        configurationService.getAccountDataURI(),
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .header("Authorization", "Bearer " + token)
                        .DELETE()
                        .timeout(
                                Duration.ofMillis(
                                        configurationService.getAccountDataApiCallTimeout()))
                        .build();
        return sendRequest(request);
    }

    private HttpResponse<String> sendRequest(HttpRequest request)
            throws UnsuccessfulAccountDataApiResponseException {
        int count = 0;
        do {
            try {
                if (count > 0) LOG.warn("Retrying Account Data API request after timeout");
                count++;
                return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (HttpTimeoutException e) {
                LOG.warn(format("Timeout on attempt %d when calling Account Data API", count));
                if (count >= MAX_TRIES) {
                    throw timeoutException(configurationService.getAccountDataApiCallTimeout(), e);
                }
            } catch (IOException e) {
                throw ioException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw interruptedException(e);
            }
        } while (count < MAX_TRIES);
        throw ioException(new IOException("Unexpected state in retry loop"));
    }
}
