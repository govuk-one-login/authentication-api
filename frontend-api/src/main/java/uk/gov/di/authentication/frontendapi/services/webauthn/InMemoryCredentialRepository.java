package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * InMemoryCredentialRepository is not intended to exist for long. This in memory version is a dummy
 * implementation to allow us to make some earlier progress on the server implementation.
 */
public class InMemoryCredentialRepository implements CredentialRepository {

    public static class Store {

        public record Credential(
                ByteArray credentialId,
                ByteArray userHandle,
                ByteArray publicKeyCose,
                long signatureCount,
                String username) {}

        private final List<Credential> credentials = new ArrayList<>();

        public void upsert(Credential cred) {
            credentials.removeIf(c -> c.credentialId().equals(cred.credentialId()));
            credentials.add(cred);
        }

        public List<Credential> getAll() {
            return credentials;
        }
    }

    private final Store store;

    public InMemoryCredentialRepository(Store store) {
        this.store = store;
    }

    public InMemoryCredentialRepository() {
        this(new Store());
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return store.getAll().stream()
                .filter(c -> c.username().equals(username))
                .map(
                        c ->
                                PublicKeyCredentialDescriptor.builder()
                                        .id(c.credentialId())
                                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return store.getAll().stream()
                .filter(c -> c.username().equals(username))
                .map(Store.Credential::userHandle)
                .findFirst();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return store.getAll().stream()
                .filter(c -> c.userHandle().equals(userHandle))
                .map(Store.Credential::username)
                .findFirst();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return store.getAll().stream()
                .filter(
                        c ->
                                c.credentialId().equals(credentialId)
                                        && c.userHandle().equals(userHandle))
                .map(
                        c ->
                                RegisteredCredential.builder()
                                        .credentialId(c.credentialId())
                                        .userHandle(c.userHandle())
                                        .publicKeyCose(c.publicKeyCose())
                                        .signatureCount(c.signatureCount())
                                        .build())
                .findFirst();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return store.getAll().stream()
                .filter(c -> c.credentialId().equals(credentialId))
                .map(
                        c ->
                                RegisteredCredential.builder()
                                        .credentialId(c.credentialId())
                                        .userHandle(c.userHandle())
                                        .publicKeyCose(c.publicKeyCose())
                                        .signatureCount(c.signatureCount())
                                        .build())
                .collect(Collectors.toSet());
    }
}
