package uk.gov.di.authentication.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class DynamoServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());

    @Test
    void getOrGenerateSaltShouldReturnNewSaltWhenUserDoesNotHaveOne() {
        setUpDynamo();
        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt.length, equalTo(32));
        assertThat(userProfile.getSalt().array(), equalTo(salt));
        UserProfile savedProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        assertThat(savedProfile.getSalt().array(), equalTo(salt));
    }

    @Test
    void getOrGenerateSaltShouldReturnExistingSaltWhenOneExists() {
        setUpDynamo();
        byte[] existingSalt = userStore.addSalt(TEST_EMAIL);

        UserProfile userProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        byte[] salt = dynamoService.getOrGenerateSalt(userProfile);

        assertThat(salt, equalTo(existingSalt));
        UserProfile savedProfile =
                dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL).orElseThrow();
        assertThat(existingSalt, equalTo(savedProfile.getSalt().array()));
    }

    private void setUpDynamo() {
        userStore.signUp(TEST_EMAIL, "password-1", new Subject());
    }
}
