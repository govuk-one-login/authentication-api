package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

// QualityGateUnitTest
class OrchClientSessionItemTest {

    private static final String RP_PAIRWISE_ID = "rp-pairwise-id";
    private static final String PUBLIC_SUBJECT_ID = "public-subject-id";

    private static final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem()
                    .withRpPairwiseId(RP_PAIRWISE_ID)
                    .withPublicSubjectId(PUBLIC_SUBJECT_ID);

    // QualityGateRegressionTest
    @Test
    void shouldReturnRpPairwiseIdForClientsWithPairwiseSubjectType() {
        assertEquals(
                RP_PAIRWISE_ID, orchClientSession.getCorrectPairwiseIdGivenSubjectType("pairwise"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnRpPairwiseIdForClientsWithPublicSubjectType() {
        assertEquals(
                PUBLIC_SUBJECT_ID,
                orchClientSession.getCorrectPairwiseIdGivenSubjectType("public"));
    }
}
