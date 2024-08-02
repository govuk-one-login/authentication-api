package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.interventions.api.stub.entity.AccountInterventionsStore;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccountInterventionsStubStoreExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AccountInterventionsDbServiceIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String INTERNAL_PAIRWISE_ID = "test-pairwise-id";

    @RegisterExtension
    protected static final AccountInterventionsStubStoreExtension dbExtension =
            new AccountInterventionsStubStoreExtension();

    AccountInterventionsDbService dynamoAuthCodeService =
            new AccountInterventionsDbService(TEST_CONFIGURATION_SERVICE);

    @Test
    void shouldReturnAccountInterventionsStoreWhereItExists() {
        dbExtension.addAccountInterventions(INTERNAL_PAIRWISE_ID, true, true, true, true);
        Optional<AccountInterventionsStore> accountInterventionsStore;
        accountInterventionsStore =
                dynamoAuthCodeService.getAccountInterventions(INTERNAL_PAIRWISE_ID);

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
                dynamoAuthCodeService.getAccountInterventions(INTERNAL_PAIRWISE_ID);

        assertTrue(accountInterventionsStore.isEmpty());
    }
}
