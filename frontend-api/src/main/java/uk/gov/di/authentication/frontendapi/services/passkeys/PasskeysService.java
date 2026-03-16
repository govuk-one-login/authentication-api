package uk.gov.di.authentication.frontendapi.services.passkeys;

import com.google.gson.JsonParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeyRetrieveError;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.shared.entity.Result;
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
    private static final Logger LOG = LogManager.getLogger(PasskeysService.class);

    public PasskeysService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        httpClient = HttpClientHelper.newInstrumentedHttpClient();
    }

    public PasskeysService(ConfigurationService configurationService, HttpClient httpClient) {
        this.configurationService = configurationService;
        this.httpClient = httpClient;
    }

    public Result<PasskeyRetrieveError, Boolean> hasActivePasskey(String publicSubjectId)
            throws IOException, InterruptedException {
        var accountDataBaseUri = configurationService.getAccountDataURI();
        var getPasskeysRequestUri =
                buildURI(
                        accountDataBaseUri,
                        "/accounts/" + publicSubjectId + "/authenticators/passkeys");
        var request = HttpRequest.newBuilder(getPasskeysRequestUri).build();
        LOG.info("Sending request to account data api retrieve endpoint");
        var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (httpResponse.statusCode() != 200) {
            LOG.warn(
                    "Error response received from retrieved passkeys endpoint, http status code {}",
                    httpResponse.statusCode());
            return Result.failure(PasskeyRetrieveError.ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE);
        }

        LOG.info("Successful response received from retrieve passkeys endpoint");
        var passkeyRetrieveResponse = parseResponse(httpResponse);
        var hasAnActivePasskey = !passkeyRetrieveResponse.passkeys().isEmpty();
        return Result.success(hasAnActivePasskey);
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
