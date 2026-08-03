package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class InactiveAccountDataExportBatchWriteServiceTest {

    @Test
    void shouldAccumulateItemsInBuffer() {
        int itemCount = 10;
        var service = new InactiveAccountDataExportBatchWriteService();

        assertDoesNotThrow(
                () -> {
                    for (int i = 0; i < itemCount; i++) {
                        service.add(createTrackerItem(i));
                    }
                });
    }

    private InactiveAccountTrackerItem createTrackerItem(int index) {
        return new InactiveAccountTrackerItem()
                .withDateForDeletion("2029-01-15")
                .withCommonSubjectId("subject-" + index)
                .withPublicSubjectId("public-subject-" + index)
                .withEmailAddress("user" + index + "@example.com");
    }
}
