package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import uk.gov.di.authentication.frontendapi.entity.JwksServiceFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

public class RemoteJwksService {
    private static RemoteJwksService remoteJwksService;
    private final HttpClient httpClient;
    private final ConfigurationService configurationService;
    private final String jwksUrl;

    public RemoteJwksService(
            ConfigurationService configurationService, String jwksUrl, HttpClient httpClient) {
        this.configurationService = configurationService;
        this.jwksUrl = jwksUrl;
        this.httpClient = httpClient;
    }

    public static RemoteJwksService getInstance(
            ConfigurationService configurationService, String jwksUrl) {
        if (remoteJwksService == null) {
            remoteJwksService =
                    new RemoteJwksService(
                            configurationService, jwksUrl, HttpClient.newHttpClient());
        }
        return remoteJwksService;
    }

    private Result<JwksServiceFailureReason, List<JWK>> getJwksResult() {
        var request =
                HttpRequest.newBuilder(URI.create(jwksUrl))
                        .GET()
                        .timeout(
                                Duration.ofMillis(
                                        configurationService.getRemoteJwksServiceCallTimeout()))
                        .build();

        HttpResponse<String> response;
        String jwksJson = null;
        int attemptCount = 0;
        int maxAttempts = 3;

        while (attemptCount <= maxAttempts) {
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                jwksJson = response.body();
                break;
            } catch (IOException ioException) {
                if (attemptCount == maxAttempts) {
                    return Result.failure(JwksServiceFailureReason.IO_FAILURE);
                } else {
                    attemptCount++;
                }
            } catch (InterruptedException interruptedException) {
                if (attemptCount == maxAttempts) {
                    return Result.failure(JwksServiceFailureReason.INTERRUPTED_FAILURE);
                } else {
                    attemptCount++;
                }
            }
        }

        JWKSet jwks;
        try {
            jwks = JWKSet.parse(jwksJson);
        } catch (ParseException parseException) {
            return Result.failure(JwksServiceFailureReason.PARSE_FAILURE);
        }
        return Result.success(jwks.getKeys());
    }

    public Result<JwksServiceFailureReason, JWK> getJwkByKeyType(KeyType keyType) {
        Result<JwksServiceFailureReason, List<JWK>> jwksResult = getJwksResult();

        return jwksResult.flatMap(
                jwks -> {
                    Optional<JWK> key =
                            jwks.stream()
                                    .filter(jwk -> jwk.getKeyType().equals(keyType))
                                    .findFirst();

                    return key.<Result<JwksServiceFailureReason, JWK>>map(Result::success)
                            .orElseGet(
                                    () -> Result.failure(JwksServiceFailureReason.NO_MATCHING_KEY));
                });
    }
}
