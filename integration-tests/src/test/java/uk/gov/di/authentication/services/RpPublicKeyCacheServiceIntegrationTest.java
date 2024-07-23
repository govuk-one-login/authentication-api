package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.RpPublicKeyCache;
import uk.gov.di.orchestration.sharedtest.extensions.RpPublicKeyCacheExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class RpPublicKeyCacheServiceIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String KEY_ID = "test-key-id";
    private static final String PUBLIC_KEY = "test-public-key";

    @RegisterExtension
    protected static final RpPublicKeyCacheExtension rpPublicKeyCacheExtension =
            new RpPublicKeyCacheExtension(180);

    @Test
    void shouldAddAndRetrieveUserInfo() {
        rpPublicKeyCacheExtension.addRpPublicKeyCacheData(CLIENT_ID, KEY_ID, PUBLIC_KEY);

        Optional<RpPublicKeyCache> retrievedUserInfo =
                rpPublicKeyCacheExtension.getRpPublicKeyCacheData(CLIENT_ID, KEY_ID);

        assertThat(retrievedUserInfo.isPresent(), equalTo(true));
        assertThat(retrievedUserInfo.get().getClientId(), equalTo(CLIENT_ID));
        assertThat(retrievedUserInfo.get().getKeyId(), equalTo(KEY_ID));
        assertThat(retrievedUserInfo.get().getPublicKey(), equalTo(PUBLIC_KEY));
    }
}
