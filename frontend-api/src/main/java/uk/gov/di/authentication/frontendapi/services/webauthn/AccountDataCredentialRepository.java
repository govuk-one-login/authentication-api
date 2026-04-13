package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;

import java.util.Optional;
import java.util.Set;

public class AccountDataCredentialRepository implements CredentialRepository {

    private final PasskeysService passkeysService;

    public AccountDataCredentialRepository(PasskeysService passkeysService) {
        this.passkeysService = passkeysService;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        throw new UnsupportedOperationException("Not yet implemented");
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
