package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import com.nimbusds.openid.connect.sdk.SubjectType;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static java.util.Collections.singletonList;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;

public class ClientConfigValidationService {

    public static final ErrorObject INVALID_POST_LOGOUT_URI =
            new ErrorObject("invalid_client_metadata", "Invalid Post logout redirect URIs");
    public static final ErrorObject INVALID_SCOPE =
            new ErrorObject("invalid_client_metadata", "Insufficient Scope");
    public static final ErrorObject INVALID_PUBLIC_KEY_SOURCE =
            new ErrorObject("invalid_client_metadata", "Invalid Public Key Source");
    public static final ErrorObject INCONSISTENT_PUBLIC_KEY_SOURCE =
            new ErrorObject("invalid_client_metadata", "Inconsistent Public Key Source");
    public static final ErrorObject INVALID_PUBLIC_KEY =
            new ErrorObject("invalid_client_metadata", "Invalid Public Key");
    public static final ErrorObject INVALID_JWKS_URI =
            new ErrorObject("invalid_client_metadata", "Invalid JWKS URI");
    public static final ErrorObject INVALID_SERVICE_TYPE =
            new ErrorObject("invalid_client_metadata", "Invalid Service Type");
    public static final ErrorObject INVALID_SUBJECT_TYPE =
            new ErrorObject("invalid_client_metadata", "Invalid Subject Type");
    public static final ErrorObject INVALID_CLAIM =
            new ErrorObject("invalid_client_metadata", "Insufficient Claim");
    public static final ErrorObject INVALID_SECTOR_IDENTIFIER_URI =
            new ErrorObject("invalid_client_metadata", "Invalid Sector Identifier URI");
    public static final ErrorObject INVALID_CLIENT_TYPE =
            new ErrorObject("invalid_client_metadata", "Invalid Client Type");
    public static final ErrorObject INVALID_CLIENT_LOCS =
            new ErrorObject("invalid_client_metadata", "Invalid Accepted Levels of Confidence");
    public static final ErrorObject INVALID_ID_TOKEN_SIGNING_ALGORITHM =
            new ErrorObject("invalid_client_metadata", "Invalid ID Token Signing Algorithm");
    public static final ErrorObject INVALID_CHANNEL =
            new ErrorObject("invalid_client_metadata", "Invalid Channel");
    public static final ErrorObject INVALID_LANDING_PAGE_URL =
            new ErrorObject("invalid_client_metadata", "Invalid Landing Page URI");

    private static final Set<String> VALID_ID_TOKEN_SIGNING_ALGORITHMS =
            Stream.of(ES256.getName(), RS256.getName()).collect(Collectors.toSet());

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
        if (!Optional.ofNullable(registrationRequest.getSectorIdentifierUri())
                .map(t -> areUrisValid(singletonList(t)))
                .orElse(true)) {
            return Optional.of(INVALID_SECTOR_IDENTIFIER_URI);
        }
        if (!Optional.ofNullable(registrationRequest.getBackChannelLogoutUri())
                .map(t -> areUrisValid(singletonList(t)))
                .orElse(true)) {
            return Optional.of(RegistrationError.INVALID_REDIRECT_URI);
        }
        if (!Optional.ofNullable(registrationRequest.getPublicKeySource())
                .map(this::isPublicKeySourceValid)
                .orElse(true)) {
            return Optional.of(INVALID_PUBLIC_KEY_SOURCE);
        }
        if (!Optional.ofNullable(registrationRequest.getPublicKey())
                .map(this::isPublicKeyValid)
                .orElse(true)) {
            return Optional.of(INVALID_PUBLIC_KEY);
        }
        if (!Optional.ofNullable(registrationRequest.getJwksUrl())
                .map(uri -> areUrisValid(singletonList(uri)))
                .orElse(true)) {
            return Optional.of(INVALID_JWKS_URI);
        }
        if (!isPublicKeySourceConsistent(
                registrationRequest.getPublicKeySource(),
                registrationRequest.getPublicKey(),
                registrationRequest.getJwksUrl(),
                false)) {
            return Optional.of(INCONSISTENT_PUBLIC_KEY_SOURCE);
        }
        if (!ValidScopes.areScopesValidAndPublic(registrationRequest.getScopes())) {
            return Optional.of(INVALID_SCOPE);
        }
        if (!isValidServiceType(registrationRequest.getServiceType())) {
            return Optional.of(INVALID_SERVICE_TYPE);
        }
        if (!isValidSubjectType(registrationRequest.getSubjectType())) {
            return Optional.of(INVALID_SUBJECT_TYPE);
        }
        if (!Optional.ofNullable(registrationRequest.getClaims())
                .map(this::areClaimsValid)
                .orElse(true)) {
            return Optional.of(INVALID_CLAIM);
        }
        if (Arrays.stream(ClientType.values())
                .noneMatch(t -> t.getValue().equals(registrationRequest.getClientType()))) {
            return Optional.of(INVALID_CLIENT_TYPE);
        }
        if (!areClientLoCsValid(registrationRequest.getClientLoCs())) {
            return Optional.of(INVALID_CLIENT_LOCS);
        }
        if (!Optional.ofNullable(registrationRequest.getIdTokenSigningAlgorithm())
                .map(this::isValidIdTokenSigningAlgorithm)
                .orElse(true)) {
            return Optional.of(INVALID_ID_TOKEN_SIGNING_ALGORITHM);
        }
        if (!Optional.ofNullable(registrationRequest.getChannel())
                .map(this::isValidChannel)
                .orElse(true)) {
            return Optional.of(INVALID_CHANNEL);
        }
        if (!Optional.ofNullable(registrationRequest.getLandingPageUrl())
                .map(t -> areUrisValid(singletonList(t)))
                .orElse(true)) {
            return Optional.of(INVALID_LANDING_PAGE_URL);
        }
        return Optional.empty();
    }

    public Optional<ErrorObject> validateClientUpdateConfig(
            UpdateClientConfigRequest updateRequest) {
        if (!Optional.ofNullable(updateRequest.getPostLogoutRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(INVALID_POST_LOGOUT_URI);
        }
        if (!Optional.ofNullable(updateRequest.getRedirectUris())
                .map(this::areUrisValid)
                .orElse(true)) {
            return Optional.of(RegistrationError.INVALID_REDIRECT_URI);
        }
        if (!Optional.ofNullable(updateRequest.getPublicKeySource())
                .map(this::isPublicKeySourceValid)
                .orElse(true)) {
            return Optional.of(INVALID_PUBLIC_KEY_SOURCE);
        }
        if (!Optional.ofNullable(updateRequest.getPublicKey())
                .map(this::isPublicKeyValid)
                .orElse(true)) {
            return Optional.of(INVALID_PUBLIC_KEY);
        }
        if (!Optional.ofNullable(updateRequest.getJwksUrl())
                .map(uri -> areUrisValid(singletonList(uri)))
                .orElse(true)) {
            return Optional.of(INVALID_JWKS_URI);
        }
        if (!isPublicKeySourceConsistent(
                updateRequest.getPublicKeySource(),
                updateRequest.getPublicKey(),
                updateRequest.getJwksUrl(),
                true)) {
            return Optional.of(INCONSISTENT_PUBLIC_KEY_SOURCE);
        }
        if (!Optional.ofNullable(updateRequest.getScopes())
                .map(ValidScopes::areScopesValidAndPublic)
                .orElse(true)) {
            return Optional.of(INVALID_SCOPE);
        }
        if (!Optional.ofNullable(updateRequest.getServiceType())
                .map(this::isValidServiceType)
                .orElse(true)) {
            return Optional.of(INVALID_SERVICE_TYPE);
        }
        if (!Optional.ofNullable(updateRequest.getSectorIdentifierUri())
                .map(t -> areUrisValid(singletonList(t)))
                .orElse(true)) {
            return Optional.of(INVALID_SECTOR_IDENTIFIER_URI);
        }
        if (!Optional.ofNullable(updateRequest.getClientType())
                .map(c -> Arrays.stream(ClientType.values()).anyMatch(t -> t.getValue().equals(c)))
                .orElse(true)) {
            return Optional.of(INVALID_CLIENT_TYPE);
        }
        if (!Optional.ofNullable(updateRequest.getClientLoCs())
                .map(this::areClientLoCsValid)
                .orElse(true)) {
            return Optional.of(INVALID_CLIENT_LOCS);
        }
        if (!Optional.ofNullable(updateRequest.getIdTokenSigningAlgorithm())
                .map(this::isValidIdTokenSigningAlgorithm)
                .orElse(true)) {
            return Optional.of(INVALID_ID_TOKEN_SIGNING_ALGORITHM);
        }
        if (!Optional.ofNullable(updateRequest.getLandingPageUrl())
                .map(t -> areUrisValid(singletonList(t)))
                .orElse(true)) {
            return Optional.of(INVALID_LANDING_PAGE_URL);
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

    private boolean isPublicKeySourceValid(String publicKeySource) {
        return Arrays.stream(PublicKeySource.values())
                .map(PublicKeySource::getValue)
                .anyMatch(pks -> pks.equals(publicKeySource));
    }

    private boolean isPublicKeySourceConsistent(
            String publicKeySource, String publicKey, String jwksUri, boolean isUpdate) {
        return (publicKeySource == null && (isUpdate || publicKey != null) && jwksUri == null)
                || (PublicKeySource.STATIC.getValue().equals(publicKeySource)
                        && publicKey != null
                        && jwksUri == null)
                || (PublicKeySource.JWKS.getValue().equals(publicKeySource)
                        && publicKey == null
                        && jwksUri != null);
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

    private boolean isValidServiceType(String serviceType) {
        return serviceType.equalsIgnoreCase(String.valueOf(MANDATORY))
                || serviceType.equalsIgnoreCase(String.valueOf(OPTIONAL));
    }

    private boolean isValidSubjectType(String subjectType) {
        return List.of(SubjectType.PUBLIC.toString(), SubjectType.PAIRWISE.toString())
                .contains(subjectType);
    }

    private boolean areClaimsValid(List<String> claims) {
        for (String claim : claims) {
            if (ValidClaims.getAllValidClaims().stream().noneMatch(t -> t.equals(claim))) {
                return false;
            }
        }
        return true;
    }

    private boolean areClientLoCsValid(List<String> clientLoCs) {
        for (String clientLoC : clientLoCs) {
            if (LevelOfConfidence.getAllSupportedLevelOfConfidenceValues().stream()
                    .noneMatch(t -> t.equals(clientLoC))) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidIdTokenSigningAlgorithm(String idTokenSigningAlgorithm) {
        return VALID_ID_TOKEN_SIGNING_ALGORITHMS.contains(idTokenSigningAlgorithm);
    }

    private boolean isValidChannel(String channel) {
        return Arrays.stream(Channel.values())
                .map(Channel::getValue)
                .anyMatch(pks -> pks.equals(channel));
    }
}
