package uk.gov.di.authentication.frontendapi.services.passkeys;

import com.google.gson.JsonParseException;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.shared.helpers.HttpClientHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class PasskeysService {
    private final ConfigurationService configurationService;
    HttpClient httpClient;
    private final SerializationService serializationService = SerializationService.getInstance();

    public PasskeysService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        httpClient = HttpClientHelper.newInstrumentedHttpClient();
    }

    public PasskeysService(ConfigurationService configurationService, HttpClient httpClient) {
        this.configurationService = configurationService;
        this.httpClient = httpClient;
    }

    public boolean hasActivePasskey(String publicSubjectId)
            throws IOException, InterruptedException {
        var accountDataBaseUri = configurationService.getAccountDataURI();
        var getPasskeysRequestUri =
                buildURI(
                        accountDataBaseUri,
                        "/accounts/" + publicSubjectId + "/authenticators/passkeys");
        var request = HttpRequest.newBuilder(getPasskeysRequestUri).build();
        var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        var passkeyRetrieveResponse = parseResponse(httpResponse);
        return !passkeyRetrieveResponse.passkeys().isEmpty();
    }

    private PasskeysRetrieveResponse parseResponse(HttpResponse<String> response) {
        try {
            return serializationService.readValue(
                    response.body(), PasskeysRetrieveResponse.class, true);
        } catch (Json.JsonException | JsonParseException e) {
            throw new RuntimeException("TODO");
        }
    }
}
