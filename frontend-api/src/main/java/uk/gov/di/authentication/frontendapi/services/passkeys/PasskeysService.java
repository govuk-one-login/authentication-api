package uk.gov.di.authentication.frontendapi.services.passkeys;

import com.google.gson.JsonParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeyRetrieveError;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.HttpClientHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.temporal.ChronoUnit;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

public class PasskeysService {
    private final ConfigurationService configurationService;
    HttpClient httpClient;
    private final SerializationService serializationService = SerializationService.getInstance();
    private final AccessTokenConstructorService accessTokenConstructorService;
    private static final Logger LOG = LogManager.getLogger(PasskeysService.class);

    private final NowHelper.NowClock nowClock = new NowHelper.NowClock(Clock.systemUTC());
    private static final Long ADAPI_ACCESS_TOKEN_LIFETIME = 5L;

    public PasskeysService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accessTokenConstructorService =
                new AccessTokenConstructorService(configurationService);
        httpClient = HttpClientHelper.newInstrumentedHttpClient();
    }

    public PasskeysService(
            ConfigurationService configurationService,
            HttpClient httpClient,
            AccessTokenConstructorService accessTokenConstructorService) {
        this.configurationService = configurationService;
        this.httpClient = httpClient;
        this.accessTokenConstructorService = accessTokenConstructorService;
    }

    public Result<PasskeyRetrieveError, Boolean> hasActivePasskey(
            String publicSubjectId, String sessionId) {
        return retrievePasskeys(publicSubjectId, sessionId)
                .map(response -> !response.passkeys().isEmpty());
    }

    public Result<PasskeyRetrieveError, PasskeysRetrieveResponse> retrievePasskeys(
            String publicSubjectId, String sessionId) {

        var accountDataApiAccessTokenResult =
                createAccountDataApiAccessToken(publicSubjectId, sessionId);
        if (accountDataApiAccessTokenResult.isFailure()) {
            return Result.failure(accountDataApiAccessTokenResult.getFailure());
        }

        var accountDataBaseUri = configurationService.getAccountDataURI();
        var getPasskeysRequestUri =
                buildURI(
                        accountDataBaseUri,
                        "/accounts/" + publicSubjectId + "/authenticators/passkeys");
        var request =
                HttpRequest.newBuilder(getPasskeysRequestUri)
                        .header(
                                "Authorization",
                                accountDataApiAccessTokenResult
                                        .getSuccess()
                                        .toAuthorizationHeader())
                        .build();
        LOG.info("Sending request to account data api retrieve endpoint");
        try {
            var httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (httpResponse.statusCode() != 200) {
                LOG.warn(
                        "Error response received from retrieved passkeys endpoint, http status code {}",
                        httpResponse.statusCode());
                return Result.failure(PasskeyRetrieveError.ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE);
            }

            LOG.info("Successful response received from retrieve passkeys endpoint");
            return parseResponse(httpResponse);
        } catch (IOException e) {
            LOG.error("IOException in retrieve passkeys", e);
            return Result.failure(PasskeyRetrieveError.IO_EXCEPTION);
        } catch (InterruptedException e) {
            if (e.getCause() instanceof LinkageError) {
                // In rare cases we see a linkage error within the HTTP Client
                // which fails all future requests made by the lambda
                // As a temporary measure we crash the lambda to force a restart
                LOG.error("Linkage error making passkey retrieve request, exiting with fault");
                System.exit(1);
            }
            LOG.error("Interrupted exception in retrieve passkeys");
            Thread.currentThread().interrupt();
            return Result.failure(PasskeyRetrieveError.INTERRUPTED_EXCEPTION);
        }
    }

    private Result<PasskeyRetrieveError, PasskeysRetrieveResponse> parseResponse(
            HttpResponse<String> response) {
        try {
            var retrieveResponse =
                    serializationService.readValue(
                            response.body(), PasskeysRetrieveResponse.class, true);
            return Result.success(retrieveResponse);
        } catch (Json.JsonException | JsonParseException e) {
            LOG.error("Failed to parse passkeys retrieve response", e);
            return Result.failure(
                    PasskeyRetrieveError.ERROR_PARSING_RESPONSE_FROM_PASSKEY_RETRIEVE);
        }
    }

    private Result<PasskeyRetrieveError, BearerAccessToken> createAccountDataApiAccessToken(
            String publicSubjectId, String sessionId) {
        return accessTokenConstructorService
                .createSignedAccessToken(
                        publicSubjectId,
                        AccountDataScope.PASSKEY_RETRIEVE,
                        sessionId,
                        nowClock.now(),
                        nowClock.nowPlus(ADAPI_ACCESS_TOKEN_LIFETIME, ChronoUnit.MINUTES),
                        configurationService.getAuthToAccountDataApiAudience(),
                        configurationService.getAuthIssuerClaim(),
                        configurationService.getAMCClientId(),
                        configurationService.getAuthToAccountDataSigningKey())
                .mapFailure(
                        failure -> {
                            LOG.warn(
                                    "Error creating account data api access token. Error: {}",
                                    failure);
                            return PasskeyRetrieveError.ERROR_CREATING_ACCESS_TOKEN;
                        });
    }
}
