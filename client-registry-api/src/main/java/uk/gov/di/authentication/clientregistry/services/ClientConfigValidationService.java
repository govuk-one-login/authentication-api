package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.entity.ValidScopes;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.authentication.shared.entity.ServiceType.OPTIONAL;

public class ClientConfigValidationService {

    public static final ErrorObject INVALID_POST_LOGOUT_URI =
            new ErrorObject("invalid_client_metadata", "Invalid Post logout redirect URIs");
    public static final ErrorObject INVALID_SCOPE =
            new ErrorObject("invalid_client_metadata", "Insufficient Scope");
    public static final ErrorObject INVALID_PUBLIC_KEY =
            new ErrorObject("invalid_client_metadata", "Invalid Public Key");
    public static final ErrorObject INVALID_SERVICE_TYPE =
            new ErrorObject("invalid_client_metadata", "Invalid Service Type");

    public Optional<ErrorObject> validateClientRegistrationConfig(
            ClientRegistrationRequest registrationRequest) {
        if (!Optional.ofNullable(registrationRequest.getPostLogoutRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(INVALID_POST_LOGOUT_URI);
        }
        if (!areUrisValid(registrationRequest.getRedirectUris())) {
            return Optional.of(RegistrationError.INVALID_REDIRECT_URI);
        }
        if (!isPublicKeyValid(registrationRequest.getPublicKey())) {
            return Optional.of(INVALID_PUBLIC_KEY);
        }
        if (!areScopesValid(registrationRequest.getScopes())) {
            return Optional.of(INVALID_SCOPE);
        }
        if (!isValidServiceType(registrationRequest.getServiceType())) {
            return Optional.of(INVALID_SERVICE_TYPE);
        }
        return Optional.empty();
    }

    public Optional<ErrorObject> validateClientUpdateConfig(
            UpdateClientConfigRequest registrationRequest) {
        if (!Optional.ofNullable(registrationRequest.getPostLogoutRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(INVALID_POST_LOGOUT_URI);
        }
        if (!Optional.ofNullable(registrationRequest.getRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(RegistrationError.INVALID_REDIRECT_URI);
        }
        if (!Optional.ofNullable(registrationRequest.getPublicKey())
                .map(this::isPublicKeyValid)
                .orElse(true)) {
            return Optional.of(INVALID_PUBLIC_KEY);
        }
        if (!Optional.ofNullable(registrationRequest.getScopes())
                .map(this::areScopesValid)
                .orElse(true)) {
            return Optional.of(INVALID_SCOPE);
        }
        if (!Optional.ofNullable(registrationRequest.getServiceType())
                .map(this::isValidServiceType)
                .orElse(true)) {
            return Optional.of(INVALID_SERVICE_TYPE);
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
            if (ValidScopes.getPublicValidScopes().stream().noneMatch((t) -> t.equals(scope))) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidServiceType(String serviceType) {
        return serviceType.equalsIgnoreCase(String.valueOf(MANDATORY))
                || serviceType.equalsIgnoreCase(String.valueOf(OPTIONAL));
    }
}
