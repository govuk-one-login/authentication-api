package uk.gov.di.authentication.oidc.helper;

import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.oidc.helper.TestIdGeneratorHelper.runWithIds;
import static uk.gov.di.authentication.oidc.helper.TestIdGeneratorHelper.runWithIncrementalIds;

class TestIdGeneratorHelperTest {
    @Test
    void shouldUseIdsProvidedForMock() {
        assertEquals(
                "test-id-1,test-id-2,test-id-3",
                runWithIds(this::generateId, List.of("test-id-1", "test-id-2", "test-id-3")));
    }

    @Test
    void shouldUseIncrementalIdsForMock() {
        var prefix = "test-id-";
        assertEquals(
                "test-id-1,test-id-2,test-id-3", runWithIncrementalIds(this::generateId, prefix));
    }

    private String generateId() {
        return String.format(
                "%s,%s,%s", IdGenerator.generate(), IdGenerator.generate(), IdGenerator.generate());
    }
}
