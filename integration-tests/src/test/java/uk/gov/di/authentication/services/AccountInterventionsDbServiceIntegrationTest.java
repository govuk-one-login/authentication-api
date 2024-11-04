package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.interventions.api.stub.entity.AccountInterventionsStore;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubStoreExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountInterventionsDbServiceIntegrationTest {

    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";

    @RegisterExtension
    protected static final AccountInterventionsStubStoreExtension dbExtension =
            new AccountInterventionsStubStoreExtension();

    AccountInterventionsDbService dynamoAuthCodeService =
            new AccountInterventionsDbService(ConfigurationService.getInstance());

    @Test
    void shouldReturnAccountInterventionsStoreWhereItExists() {
        dbExtension.addAccountInterventions(
                TEST_INTERNAL_COMMON_SUBJECT_ID, true, true, true, true);
        Optional<AccountInterventionsStore> accountInterventionsStore;
        accountInterventionsStore =
                dynamoAuthCodeService.getAccountInterventions(TEST_INTERNAL_COMMON_SUBJECT_ID);

        assertTrue(accountInterventionsStore.isPresent());
        assertTrue(accountInterventionsStore.get().isBlocked());
        assertTrue(accountInterventionsStore.get().isSuspended());
        assertTrue(accountInterventionsStore.get().isReproveIdentity());
        assertTrue(accountInterventionsStore.get().isResetPassword());
    }

    @Test
    void shouldReturnNoneWhereThePairwiseIdDoesNotExist() {
        dbExtension.addAccountInterventions("anotherPairwiseId", true, true, true, true);
        var accountInterventionsStore =
                dynamoAuthCodeService.getAccountInterventions(TEST_INTERNAL_COMMON_SUBJECT_ID);

        assertTrue(accountInterventionsStore.isEmpty());
    }
}
