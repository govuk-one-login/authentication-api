package uk.gov.di.authentication.ticf.cri.stub.lambda.services;

import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.ticf.cri.stub.lambda.entity.TICFCRIStore;

import java.util.List;
import java.util.Optional;

public class TICFCRIDbService extends BaseDynamoService<TICFCRIStore> {
    public TICFCRIDbService(ConfigurationService configurationService) {
        super(TICFCRIStore.class, "stub-ticf-cri", configurationService);
    }

    public void addTICFCRIDetails(
            String internalPairwiseId,
            String interventionCode,
            String interventionReason,
            List<String> ci,
            int sleep,
            int errorStatus) {
        var TICFCRIDetails =
                get(internalPairwiseId)
                        .orElse(
                                new TICFCRIStore()
                                        .withInternalPairwiseId(internalPairwiseId)
                                        .withInterventionCode(interventionCode)
                                        .withInterventionReason(interventionReason)
                                        .withCi(ci))
                                        .withErrorStatus(sleep)
                                        .withSleep(errorStatus);
        update(TICFCRIDetails);
    }

    public Optional<TICFCRIStore> getTICFCRIDetails(String internalPairwiseId) {
        return get(internalPairwiseId);
    }
}
