package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationService;
import uk.gov.di.authentication.sharedtest.extensions.AccountModifiersStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class DynamoDeleteServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";

    @RegisterExtension
    protected static final UserStoreExtension userStoreExtension = new UserStoreExtension();

    @RegisterExtension
    protected static final AccountModifiersStoreExtension accountModifiersExtension =
            new AccountModifiersStoreExtension();

    DynamoDeleteService dynamoDeleteService =
            new DynamoDeleteService(ConfigurationService.getInstance());
    DynamoAuthenticationService dynamoAuthenticationService =
            new DynamoAuthenticationService(ConfigurationService.getInstance());
    DynamoAccountModifiersService dynamoAccountModifiersService =
            new DynamoAccountModifiersService(ConfigurationService.getInstance());

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());

    @Test
    void shouldDeleteAccountAndEntryInAccountModifiersIfPresent() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);
        accountModifiersExtension.setAccountRecoveryBlock(internalCommonSubjectId);

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId);

        var userProfile = dynamoAuthenticationService.getUserProfileByEmail(TEST_EMAIL);
        var userCredentials = dynamoAuthenticationService.getUserCredentialsFromEmail(TEST_EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }

    @Test
    void shouldDeleteAccountWhenEntryInAccountModifiersIsNotPresent() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId);

        var userProfile = dynamoAuthenticationService.getUserProfileByEmail(TEST_EMAIL);
        var userCredentials = dynamoAuthenticationService.getUserCredentialsFromEmail(TEST_EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }
}
