package uk.gov.di.services;

import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.UpdateClientConfigRequest;
import uk.gov.di.entity.ValidScopes;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class ClientConfigValidationService {

    public Optional<ErrorResponse> validateClientRegistrationConfig(
            ClientRegistrationRequest registrationRequest) {
        if (!Optional.ofNullable(registrationRequest.getPostLogoutRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(ErrorResponse.ERROR_1021);
        }
        if (!areUrisValid(registrationRequest.getRedirectUris())) {
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        if (!isPublicKeyValid(registrationRequest.getPublicKey())) {
            return Optional.of(ErrorResponse.ERROR_1023);
        }
        if (!areScopesValid(registrationRequest.getScopes())) {
            return Optional.of(ErrorResponse.ERROR_1024);
        }
        return Optional.empty();
    }

    public Optional<ErrorResponse> validateClientUpdateConfig(
            UpdateClientConfigRequest registrationRequest) {
        if (!Optional.ofNullable(registrationRequest.getPostLogoutRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(ErrorResponse.ERROR_1021);
        }
        if (!Optional.ofNullable(registrationRequest.getRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(ErrorResponse.ERROR_1022);
        }
        if (!Optional.ofNullable(registrationRequest.getPublicKey())
                .map(this::isPublicKeyValid)
                .orElse(true)) {
            return Optional.of(ErrorResponse.ERROR_1023);
        }
        if (!Optional.ofNullable(registrationRequest.getScopes())
                .map(this::areScopesValid)
                .orElse(true)) {
            return Optional.of(ErrorResponse.ERROR_1024);
        }
        return Optional.empty();
    }

    private boolean areUrisValid(List<String> uris) {
        try {
            for (String uri : uris) {
                new URL(uri);
            }
        } catch (MalformedURLException e) {
            return false;
        }
        return true;
    }

    private boolean isPublicKeyValid(String publicKey) {
        try {
            byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
            X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            kf.generatePublic(x509publicKey);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private boolean areScopesValid(List<String> scopes) {
        for (String scope : scopes) {
            if (Arrays.stream(ValidScopes.values())
                    .noneMatch((t) -> t.scopesLowerCase().equals(scope))) {
                return false;
            }
        }
        return true;
    }
}
