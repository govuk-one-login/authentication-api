package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.HttpClientHelper;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.interruptedException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.ioException;
import static uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException.timeoutException;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class AccountDataApiService {
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

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (HttpTimeoutException e) {
            throw timeoutException(configurationService.getAccountDataApiCallTimeout(), e);
        } catch (IOException e) {
            throw ioException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw interruptedException(e);
        }
    }
}
