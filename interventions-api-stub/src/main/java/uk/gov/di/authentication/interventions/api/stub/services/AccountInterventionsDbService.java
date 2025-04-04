package uk.gov.di.authentication.interventions.api.stub.services;

import uk.gov.di.authentication.interventions.api.stub.entity.AccountInterventionsStore;
import uk.gov.di.authentication.shared.annotations.Instrumented;
import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

public class AccountInterventionsDbService extends BaseDynamoService<AccountInterventionsStore> {
    public AccountInterventionsDbService(ConfigurationService configurationService) {
        super(AccountInterventionsStore.class, "stub-account-interventions", configurationService);
    }

    @Instrumented
    public void addAccountInterventions(
            String internalPairwiseId,
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword) {

        var accountInterventions =
                get(internalPairwiseId)
                        .orElse(
                                new AccountInterventionsStore()
                                        .withPairwiseId(internalPairwiseId)
                                        .withBlocked(blocked)
                                        .withSuspended(suspended)
                                        .withReproveIdentity(reproveIdentity)
                                        .withResetPassword(resetPassword));
        update(accountInterventions);
    }

    @Instrumented
    public static AccountInterventionsStore newStore() {
        return new AccountInterventionsStore();
    }

    @Instrumented
    public Optional<AccountInterventionsStore> getAccountInterventions(String internalPairwiseId) {
        return get(internalPairwiseId);
    }
}
