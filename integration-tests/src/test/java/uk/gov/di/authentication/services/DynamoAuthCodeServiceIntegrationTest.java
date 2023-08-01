package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.sharedtest.extensions.AuthCodeExtension;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;

class DynamoAuthCodeServiceIntegrationTest {

    private static final String SUBJECT_ID = "test-subject-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String REQUESTED_SCOPE_CLAIMS = "test-requested-scope-claims";
    private static final boolean HAS_BEEN_USED = false;

    @RegisterExtension
    protected static final AuthCodeExtension authCodeExtension = new AuthCodeExtension(180);

    DynamoAuthCodeService dynamoAuthCodeService =
            new DynamoAuthCodeService(ConfigurationService.getInstance(), true);

    private void setUpDynamo() {
        authCodeExtension.saveAuthCode(
                SUBJECT_ID, AUTH_CODE, REQUESTED_SCOPE_CLAIMS, HAS_BEEN_USED);
    }

    @Test
    void shouldUpdateHasBeenUsed() {
        setUpDynamo();

        dynamoAuthCodeService.updateHasBeenUsed(SUBJECT_ID, true);
        var updatedAuthCode =
                dynamoAuthCodeService.getAuthCodeStore(SUBJECT_ID).orElseGet(AuthCodeStore::new);

        assertThat(updatedAuthCode.isHasBeenUsed(), equalTo(true));
    }

    @Test
    void shouldDeleteAuthCode() {
        setUpDynamo();

        dynamoAuthCodeService.deleteAuthCode(SUBJECT_ID);
        var updatedAuthCode = dynamoAuthCodeService.getAuthCodeStore(SUBJECT_ID);

        assertFalse(updatedAuthCode.isPresent());
    }
}
