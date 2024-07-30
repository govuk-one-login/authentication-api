package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.extensions.AccountModifiersStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;

class DynamoDeleteServiceIntegrationTest {

    private static final Subject SUBJECT = new Subject();

    @RegisterExtension
    protected static final UserStoreExtension userStoreExtension = new UserStoreExtension();

    @RegisterExtension
    protected static final AccountModifiersStoreExtension accountModifiersExtension =
            new AccountModifiersStoreExtension();

    DynamoDeleteService dynamoDeleteService =
            new DynamoDeleteService(ConfigurationService.getInstance());
    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());
    DynamoAccountModifiersService dynamoAccountModifiersService =
            new DynamoAccountModifiersService(ConfigurationService.getInstance());

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), INTERNAL_SECTOR_HOST, SaltHelper.generateNewSalt());

    @Test
    void shouldDeleteAccountAndEntryInAccountModifiersIfPresent() {
        userStoreExtension.signUp(EMAIL, PASSWORD, SUBJECT);
        accountModifiersExtension.setAccountRecoveryBlock(internalCommonSubjectId);

        dynamoDeleteService.deleteAccount(EMAIL, internalCommonSubjectId);

        var userProfile = dynamoService.getUserProfileByEmail(EMAIL);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }

    @Test
    void shouldDeleteAccountWhenEntryInAccountModifiersIsNotPresent() {
        userStoreExtension.signUp(EMAIL, PASSWORD, SUBJECT);

        dynamoDeleteService.deleteAccount(EMAIL, internalCommonSubjectId);

        var userProfile = dynamoService.getUserProfileByEmail(EMAIL);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }
}
