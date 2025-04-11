package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.sharedtest.extensions.AuthCodeExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL;
import static uk.gov.di.authentication.external.entity.AuthUserInfoClaims.EMAIL_VERIFIED;

class DynamoAuthCodeServiceIntegrationTest {

    private static final String SUBJECT_ID = "test-subject-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final boolean HAS_BEEN_USED = false;
    private static final boolean IS_NEW_ACCOUNT = false;
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final Long PASSWORD_RESET_TIME = 1696869005821L;
    private static final String TEST_JOURNEY_ID = "client-session-id";

    @RegisterExtension
    protected static final AuthCodeExtension authCodeExtension = new AuthCodeExtension(180);

    DynamoAuthCodeService dynamoAuthCodeService =
            new DynamoAuthCodeService(ConfigurationService.getInstance());

    private void setUpDynamo() {
        authCodeExtension.saveAuthCode(
                SUBJECT_ID,
                AUTH_CODE,
                List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                HAS_BEEN_USED,
                TEST_SECTOR_IDENTIFIER,
                IS_NEW_ACCOUNT,
                TEST_JOURNEY_ID);
    }

    @Test
    void shouldUpdateHasBeenUsed() {
        setUpDynamo();

        dynamoAuthCodeService.updateHasBeenUsed(AUTH_CODE, true);
        var updatedAuthCode =
                dynamoAuthCodeService.getAuthCodeStore(AUTH_CODE).orElseGet(AuthCodeStore::new);

        assertThat(updatedAuthCode.isHasBeenUsed(), equalTo(true));
    }

    @Test
    void shouldDeleteAuthCode() {
        setUpDynamo();

        dynamoAuthCodeService.deleteAuthCode(SUBJECT_ID);
        var updatedAuthCode = dynamoAuthCodeService.getAuthCodeStore(SUBJECT_ID);

        assertFalse(updatedAuthCode.isPresent());
    }

    @Test
    void shouldStoreAnAuthCodeWithoutPasswordResetTime() {
        dynamoAuthCodeService.saveAuthCode(
                SUBJECT_ID,
                AUTH_CODE,
                List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                HAS_BEEN_USED,
                TEST_SECTOR_IDENTIFIER,
                IS_NEW_ACCOUNT,
                null,
                TEST_JOURNEY_ID);

        var updatedAuthCode = dynamoAuthCodeService.getAuthCodeStore(AUTH_CODE).get();
        assertEquals(AUTH_CODE, updatedAuthCode.getAuthCode());
        assertEquals(null, updatedAuthCode.getPasswordResetTime());
    }

    @Test
    void shouldStoreAnAuthCodeWithPasswordResetTime() {
        dynamoAuthCodeService.saveAuthCode(
                SUBJECT_ID,
                AUTH_CODE,
                List.of(EMAIL_VERIFIED.getValue(), EMAIL.getValue()),
                HAS_BEEN_USED,
                TEST_SECTOR_IDENTIFIER,
                IS_NEW_ACCOUNT,
                PASSWORD_RESET_TIME,
                TEST_JOURNEY_ID);

        var updatedAuthCode = dynamoAuthCodeService.getAuthCodeStore(AUTH_CODE).get();
        assertEquals(AUTH_CODE, updatedAuthCode.getAuthCode());
        assertEquals(PASSWORD_RESET_TIME, updatedAuthCode.getPasswordResetTime());
    }
}
