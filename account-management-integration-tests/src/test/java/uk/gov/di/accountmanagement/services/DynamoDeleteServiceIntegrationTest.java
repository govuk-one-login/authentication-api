package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountModifiersStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class DynamoDeleteServiceIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";

    @RegisterExtension
    protected static final UserStoreExtension userStoreExtension = new UserStoreExtension();

    @RegisterExtension
    protected static final AccountModifiersStoreExtension accountModifiersExtension =
            new AccountModifiersStoreExtension();

    DynamoDeleteService dynamoDeleteService = new DynamoDeleteService(TEST_CONFIGURATION_SERVICE);
    DynamoService dynamoService = new DynamoService(TEST_CONFIGURATION_SERVICE);
    DynamoAccountModifiersService dynamoAccountModifiersService =
            new DynamoAccountModifiersService(TEST_CONFIGURATION_SERVICE);

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());

    @Test
    void shouldDeleteAccountAndEntryInAccountModifiersIfPresent() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);
        accountModifiersExtension.setAccountRecoveryBlock(internalCommonSubjectId);

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId);

        var userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
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

        var userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }
}
