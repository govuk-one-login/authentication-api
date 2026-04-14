package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.passkeys.PasskeysRetrieveResponse;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AccountDataCredentialRepository implements CredentialRepository {

    private static final Logger LOG = LogManager.getLogger(AccountDataCredentialRepository.class);

    private final PasskeysService passkeysService;
    private final AuthenticationService authenticationService;

    public AccountDataCredentialRepository(
            PasskeysService passkeysService, AuthenticationService authenticationService) {
        this.passkeysService = passkeysService;
        this.authenticationService = authenticationService;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return retrievePasskeysForEmail(username)
                .map(
                        passkeys ->
                                passkeys.stream()
                                        .flatMap(
                                                passkey -> toCredentialDescriptor(passkey).stream())
                                        .collect(Collectors.toSet()))
                .orElse(Collections.emptySet());
    }

    private Optional<PublicKeyCredentialDescriptor> toCredentialDescriptor(
            PasskeysRetrieveResponse.PasskeyResponse passkey) {
        try {
            return Optional.of(
                    PublicKeyCredentialDescriptor.builder()
                            .id(ByteArray.fromBase64Url(passkey.passkeyId()))
                            .type(PublicKeyCredentialType.PUBLIC_KEY)
                            .build());
        } catch (Base64UrlException e) {
            LOG.warn("Invalid Base64Url credential ID, skipping passkey", e);
            return Optional.empty();
        }
    }

    private Optional<String> resolvePublicSubjectId(String email) {
        return authenticationService
                .getUserProfileByEmailMaybe(email)
                .map(UserProfile::getPublicSubjectID);
    }

    private Optional<List<PasskeysRetrieveResponse.PasskeyResponse>> retrievePasskeysForEmail(
            String email) {
        var publicSubjectId = resolvePublicSubjectId(email);
        if (publicSubjectId.isEmpty()) {
            LOG.warn("No user profile found for username");
            return Optional.empty();
        }
        var result = passkeysService.retrievePasskeys(publicSubjectId.get());
        if (result.isFailure()) {
            LOG.warn("Failed to retrieve passkeys: {}", result.getFailure());
            return Optional.empty();
        }
        return Optional.of(result.getSuccess().passkeys());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return resolvePublicSubjectId(username)
                .map(id -> new ByteArray(id.getBytes(StandardCharsets.UTF_8)));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        var publicSubjectId = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
        return authenticationService
                .getOptionalUserProfileFromPublicSubject(publicSubjectId)
                .map(UserProfile::getEmail);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
