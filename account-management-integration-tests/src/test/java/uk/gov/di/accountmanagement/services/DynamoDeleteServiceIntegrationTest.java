package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.testsupport.AuthenticatorStoreExtension;
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

class DynamoDeleteServiceIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String PUBLIC_SUBJECT_ID = new Subject().getValue();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";

    @RegisterExtension
    protected static final UserStoreExtension userStoreExtension = new UserStoreExtension();

    @RegisterExtension
    protected static final AccountModifiersStoreExtension accountModifiersExtension =
            new AccountModifiersStoreExtension();

    @RegisterExtension
    protected static final AuthenticatorStoreExtension authenticatorStoreExtension =
            new AuthenticatorStoreExtension();

    DynamoDeleteService dynamoDeleteService =
            new DynamoDeleteService(ConfigurationService.getInstance());
    DynamoService dynamoService = new DynamoService(ConfigurationService.getInstance());
    DynamoAccountModifiersService dynamoAccountModifiersService =
            new DynamoAccountModifiersService(ConfigurationService.getInstance());

    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());

    @Test
    void shouldDeleteAccountAndEntryInAccountModifiersIfPresent() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);
        accountModifiersExtension.setAccountRecoveryBlock(internalCommonSubjectId);

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId, PUBLIC_SUBJECT_ID);

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

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId, PUBLIC_SUBJECT_ID);

        var userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        var userCredentials = dynamoService.getUserCredentialsFromEmail(TEST_EMAIL);
        var accountModifiers =
                dynamoAccountModifiersService.getAccountModifiers(internalCommonSubjectId);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(Objects.isNull(userCredentials), equalTo(true));
        assertThat(accountModifiers.isEmpty(), equalTo(true));
    }

    @Test
    void shouldDeletePasskeyRecordsWhenAccountIsDeleted() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);
        authenticatorStoreExtension.addMinimalPasskey(PUBLIC_SUBJECT_ID, "credential-1");
        authenticatorStoreExtension.addMinimalPasskey(PUBLIC_SUBJECT_ID, "credential-2");

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId, PUBLIC_SUBJECT_ID);

        var userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        var authenticatorItems = authenticatorStoreExtension.getItemsForUser(PUBLIC_SUBJECT_ID);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(authenticatorItems.isEmpty(), equalTo(true));
    }

    @Test
    void shouldDeleteAccountWhenNoPasskeysExist() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId, PUBLIC_SUBJECT_ID);

        var userProfile = dynamoService.getUserProfileByEmail(TEST_EMAIL);
        var authenticatorItems = authenticatorStoreExtension.getItemsForUser(PUBLIC_SUBJECT_ID);
        assertThat(Objects.isNull(userProfile), equalTo(true));
        assertThat(authenticatorItems.isEmpty(), equalTo(true));
    }

    @Test
    void shouldDeleteAllPasskeysWhenMultipleExist() {
        userStoreExtension.signUp(TEST_EMAIL, "password-1", SUBJECT);
        authenticatorStoreExtension.addMinimalPasskey(PUBLIC_SUBJECT_ID, "credential-1");
        authenticatorStoreExtension.addMinimalPasskey(PUBLIC_SUBJECT_ID, "credential-2");
        authenticatorStoreExtension.addMinimalPasskey(PUBLIC_SUBJECT_ID, "credential-3");

        var itemsBefore = authenticatorStoreExtension.getItemsForUser(PUBLIC_SUBJECT_ID);
        assertThat(itemsBefore.size(), equalTo(3));

        dynamoDeleteService.deleteAccount(TEST_EMAIL, internalCommonSubjectId, PUBLIC_SUBJECT_ID);

        var itemsAfter = authenticatorStoreExtension.getItemsForUser(PUBLIC_SUBJECT_ID);
        assertThat(itemsAfter.isEmpty(), equalTo(true));
    }
}
