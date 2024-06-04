package uk.gov.di.authentication.clientregistry.services;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import com.nimbusds.openid.connect.sdk.SubjectType;
import software.amazon.awssdk.annotations.NotNull;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.orchestration.shared.entity.ClientConfigRequest;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.exceptions.ClientRegistrryConfigValidationException;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.shared.entity.ServiceType.OPTIONAL;

public class ClientConfigValidationService {

    public static final ErrorObject INVALID_POST_LOGOUT_URI =
            new ErrorObject("invalid_client_metadata", "Invalid Post logout redirect URIs");
    public static final ErrorObject INVALID_SCOPE =
            new ErrorObject("invalid_client_metadata", "Insufficient Scope");
    public static final ErrorObject INVALID_PUBLIC_KEY =
            new ErrorObject("invalid_client_metadata", "Invalid Public Key");
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

    public static final Set<String> VALID_ID_TOKEN_SIGNING_ALGORITHMS =
            Stream.of(ES256, RS256).map(Algorithm::getName).collect(Collectors.toSet());

    public void validateClientRegistrationConfig(ClientRegistrationRequest registrationRequest)
            throws ClientRegistrryConfigValidationException {
        validateClientConfig(registrationRequest);
        validateSubjectType(registrationRequest);
    }

    public void validateClientConfig(ClientConfigRequest configRequest)
            throws IllegalArgumentException, ClientRegistrryConfigValidationException {
        validatePostLogoutRedirectURIs(configRequest);
        validateRedirectURIs(configRequest);
        validatePublicKey(configRequest);
        validateScopes(configRequest);
        validateServiceType(configRequest);
        validateSectorIdentifierURI(configRequest);
        validateClientType(configRequest);
        validateClaims(configRequest);
        validateClientLoCs(configRequest);
        validateTokenSigningAlgorithm(configRequest);
    }

    private void validateClientType(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getClientType,
                ct -> {
                    if (!Arrays.stream(ClientType.values())
                            .map(ClientType::getValue)
                            .toList()
                            .contains(ct)) {
                        throw new ClientRegistrryConfigValidationException(INVALID_CLIENT_TYPE);
                    }
                });
    }

    private void validatePostLogoutRedirectURIs(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getPostLogoutRedirectUris,
                plrs -> {
                    for (var uri : plrs) {
                        validateUri(uri, INVALID_POST_LOGOUT_URI);
                    }
                });
    }

    private void validateRedirectURIs(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getRedirectUris,
                rs -> {
                    for (var uri : rs) {
                        validateUri(uri, RegistrationError.INVALID_REDIRECT_URI);
                    }
                });
    }

    private void validateSectorIdentifierURI(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getSectorIdentifierUri,
                si -> validateUri(si, INVALID_SECTOR_IDENTIFIER_URI));
    }

    private void validateUri(String uri, ErrorObject errorObject)
            throws ClientRegistrryConfigValidationException {
        try {
            new URL(uri);
        } catch (MalformedURLException e) {
            throw new ClientRegistrryConfigValidationException(errorObject);
        }
    }

    private void validatePublicKey(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getPublicKey,
                pk -> {
                    try {
                        byte[] decodedKey = Base64.getMimeDecoder().decode(pk);
                        X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        kf.generatePublic(x509publicKey);
                    } catch (Exception e) {
                        throw new ClientRegistrryConfigValidationException(INVALID_PUBLIC_KEY);
                    }
                });
    }

    private void validateScopes(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getScopes,
                ss -> {
                    for (String scope : ss) {
                        if (!ValidScopes.getPublicValidScopes().contains(scope)) {
                            throw new ClientRegistrryConfigValidationException(INVALID_SCOPE);
                        }
                    }
                });
    }

    private void validateServiceType(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getServiceType,
                st -> {
                    if (!(st.equalsIgnoreCase(String.valueOf(MANDATORY))
                            || st.equalsIgnoreCase(String.valueOf(OPTIONAL)))) {
                        throw new ClientRegistrryConfigValidationException(INVALID_SERVICE_TYPE);
                    }
                });
    }

    private void validateSubjectType(ClientRegistrationRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientRegistrationRequest::getSubjectType,
                st -> {
                    if (!List.of(SubjectType.PUBLIC.toString(), SubjectType.PAIRWISE.toString())
                            .contains(st)) {
                        throw new ClientRegistrryConfigValidationException(INVALID_SUBJECT_TYPE);
                    }
                });
    }

    private void validateClaims(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getClaims,
                cs -> {
                    for (String claim : cs) {
                        if (!ValidClaims.getAllValidClaims().contains(claim)) {
                            throw new ClientRegistrryConfigValidationException(INVALID_CLAIM);
                        }
                    }
                });
    }

    private void validateClientLoCs(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getClientLoCs,
                locs -> {
                    for (String loc : locs) {
                        if (!LevelOfConfidence.getAllSupportedLevelOfConfidenceValues()
                                .contains(loc)) {
                            throw new ClientRegistrryConfigValidationException(INVALID_CLIENT_LOCS);
                        }
                    }
                });
    }

    private void validateTokenSigningAlgorithm(ClientConfigRequest request)
            throws ClientRegistrryConfigValidationException {
        validateIfPresent(
                request,
                ClientConfigRequest::getIdTokenSigningAlgorithm,
                itsa -> {
                    if (!VALID_ID_TOKEN_SIGNING_ALGORITHMS.contains(itsa)) {
                        throw new ClientRegistrryConfigValidationException(
                                INVALID_ID_TOKEN_SIGNING_ALGORITHM);
                    }
                });
    }

    private <C, F> void validateIfPresent(
            C clientConfig, Function<C, F> getter, ClientConfigFieldValidator<F> validator)
            throws ClientRegistrryConfigValidationException {
        var field = getter.apply(clientConfig);
        if (field != null) {
            validator.validate(field);
        }
    }

    @FunctionalInterface()
    private interface ClientConfigFieldValidator<T> {
        void validate(@NotNull T field) throws ClientRegistrryConfigValidationException;
    }
}
