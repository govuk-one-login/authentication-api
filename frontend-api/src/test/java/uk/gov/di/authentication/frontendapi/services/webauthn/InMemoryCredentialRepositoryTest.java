package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

class InMemoryCredentialRepositoryTest {

    private InMemoryCredentialRepository repository;
    private static final String USERNAME = "testuser";
    private static final ByteArray CREDENTIAL_ID =
            new ByteArray("testcredential".getBytes(StandardCharsets.UTF_8));
    private static final ByteArray USER_HANDLE =
            new ByteArray(USERNAME.getBytes(StandardCharsets.UTF_8));
    private static final ByteArray PUBLIC_KEY =
            new ByteArray("testpublickey".getBytes(StandardCharsets.UTF_8));

    @BeforeEach
    void setUp() {
        InMemoryCredentialRepository.Store credentialStore =
                new InMemoryCredentialRepository.Store();
        repository = new InMemoryCredentialRepository(credentialStore);
        credentialStore.upsert(
                new InMemoryCredentialRepository.Store.Credential(
                        CREDENTIAL_ID, USER_HANDLE, PUBLIC_KEY, 0L, USERNAME));
    }

    @Nested
    class GetCredentialIdsForUsername {
        @Test
        void returnsCredentialIds() {
            Set<PublicKeyCredentialDescriptor> result =
                    repository.getCredentialIdsForUsername(USERNAME);

            assertThat(result, hasSize(1));
            PublicKeyCredentialDescriptor descriptor = result.iterator().next();
            assertThat(descriptor.getId(), equalTo(CREDENTIAL_ID));
            assertThat(descriptor.getType(), equalTo(PublicKeyCredentialType.PUBLIC_KEY));
        }
    }

    @Nested
    class GetUserHandleForUsername {
        @Test
        void returnsUserHandle() {
            Optional<ByteArray> result = repository.getUserHandleForUsername(USERNAME);

            assertThat(result.isPresent(), is(true));
            assertThat(result.get(), equalTo(USER_HANDLE));
        }
    }

    @Nested
    class GetUsernameForUserHandle {
        @Test
        void returnsUsername() {
            Optional<String> result = repository.getUsernameForUserHandle(USER_HANDLE);

            assertThat(result.isPresent(), is(true));
            assertThat(result.get(), equalTo(USERNAME));
        }
    }

    @Nested
    class Lookup {
        @Test
        void returnsRegisteredCredential() {
            Optional<RegisteredCredential> result = repository.lookup(CREDENTIAL_ID, USER_HANDLE);

            assertThat(result.isPresent(), is(true));
            RegisteredCredential credential = result.get();
            assertThat(credential.getCredentialId(), equalTo(CREDENTIAL_ID));
            assertThat(credential.getUserHandle(), equalTo(USER_HANDLE));
            assertThat(credential.getPublicKeyCose(), equalTo(PUBLIC_KEY));
            assertThat(credential.getSignatureCount(), equalTo(0L));
        }
    }

    @Nested
    class LookupAll {
        @Test
        void returnsCredentials() {
            Set<RegisteredCredential> result = repository.lookupAll(CREDENTIAL_ID);

            assertThat(result, hasSize(1));
            RegisteredCredential credential = result.iterator().next();
            assertThat(credential.getCredentialId(), equalTo(CREDENTIAL_ID));
        }
    }
}
