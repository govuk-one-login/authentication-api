package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InactiveAccountDataExportHandlerTest {

    private static final TableSchema<UserProfile> USER_PROFILE_SCHEMA =
            TableSchema.fromBean(UserProfile.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);
    private final Context context = mock(Context.class);

    private InactiveAccountDataExportHandler createHandler() {
        return new InactiveAccountDataExportHandler(configurationService, client);
    }

    @Test
    void shouldThrowIfRequestIsMissingRequiredFields() {
        var handler = createHandler();

        assertThrows(IllegalArgumentException.class, () -> handler.handleRequest(null, context));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        handler.handleRequest(
                                new InactiveAccountDataExportRequest(null, 5, null), context));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        handler.handleRequest(
                                new InactiveAccountDataExportRequest(10, null, null), context));
    }

    @Test
    void shouldDefaultMaxRetriesToThreeWhenNull() {
        int itemCount = 5;
        int pageSize = 5;
        mockScanWithPagination(itemCount, pageSize);

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(4, 1, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.totalItemsScanned());
    }

    @Test
    void shouldUseExplicitMaxRetriesValue() {
        int itemCount = 5;
        int pageSize = 5;
        mockScanWithPagination(itemCount, pageSize);

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(4, 1, 5);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.totalItemsScanned());
    }

    @Test
    void shouldPaginateThroughAllPagesInSegment() {
        int itemCount = 25;
        int pageSize = 5;
        mockScanWithPagination(itemCount, pageSize);

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(4, 1, null);

        var response = handler.handleRequest(request, context);

        assertEquals(itemCount, response.totalItemsScanned());
    }

    @Test
    void shouldLogErrorAndPropagateExceptionWhenScanFails() {
        when(client.scan(any(ScanRequest.class)))
                .thenThrow(
                        DynamoDbException.builder()
                                .message("Provisioned throughput exceeded")
                                .build());

        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(1, 1, null);

        assertThrows(
                DynamoDbException.class, () -> handler.handleRequest(request, context));
    }

    private Map<String, AttributeValue> createItem(int index) {
        var profile =
                new UserProfile()
                        .withEmail("user" + index + "@example.com")
                        .withCreated("2024-01-15")
                        .withUpdated("2024-06-20")
                        .withPublicSubjectID("public-subject-" + index)
                        .withSubjectID("subject-" + index)
                        .withSalt(ByteBuffer.wrap(new byte[] {(byte) index, 42}))
                        .withTermsAndConditions(
                                new TermsAndConditions("1.5", "2024-01-15T09:30:00Z"));
        return USER_PROFILE_SCHEMA.itemToMap(profile, true);
    }

    private void mockScanWithPagination(int totalItems, int pageSize) {
        List<ScanResponse> pages = buildPages(totalItems, pageSize);
        AtomicInteger callCount = new AtomicInteger(0);

        when(client.scan(any(ScanRequest.class)))
                .thenAnswer(invocation -> pages.get(callCount.getAndIncrement()));
    }

    private List<ScanResponse> buildPages(int totalItems, int pageSize) {
        List<Map<String, AttributeValue>> allItems = new ArrayList<>();
        for (int i = 1; i <= totalItems; i++) {
            allItems.add(createItem(i));
        }

        List<ScanResponse> pages = new ArrayList<>();
        for (int start = 0; start < totalItems; start += pageSize) {
            int end = Math.min(start + pageSize, totalItems);
            List<Map<String, AttributeValue>> pageItems = allItems.subList(start, end);
            boolean hasMorePages = end < totalItems;

            ScanResponse.Builder responseBuilder =
                    ScanResponse.builder()
                            .items(pageItems)
                            .count(pageItems.size())
                            .scannedCount(pageItems.size());

            if (hasMorePages) {
                responseBuilder.lastEvaluatedKey(
                        Map.of(
                                UserProfile.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("lastKey-" + end).build()));
            }

            pages.add(responseBuilder.build());
        }
        return pages;
    }
}
