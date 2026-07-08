package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class InactiveAccountDataExportHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);
    private final Context context = mock(Context.class);

    private InactiveAccountDataExportHandler createHandler() {
        return new InactiveAccountDataExportHandler(configurationService, client);
    }

    @Test
    void shouldThrowIfRequestIsNull() {
        var handler = createHandler();

        var exception =
                assertThrows(
                        IllegalArgumentException.class, () -> handler.handleRequest(null, context));

        assertTrue(exception.getMessage().contains("parallelism"));
        assertTrue(exception.getMessage().contains("totalSegments"));
    }

    @Test
    void shouldThrowIfParallelismIsNull() {
        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(null, 7);

        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> handler.handleRequest(request, context));

        assertTrue(exception.getMessage().contains("parallelism"));
        assertTrue(exception.getMessage().contains("totalSegments"));
    }

    @Test
    void shouldThrowIfTotalSegmentsIsNull() {
        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(7, null);

        var exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> handler.handleRequest(request, context));

        assertTrue(exception.getMessage().contains("parallelism"));
        assertTrue(exception.getMessage().contains("totalSegments"));
    }

    @Test
    void shouldAcceptValidRequest() {
        var handler = createHandler();
        var request = new InactiveAccountDataExportRequest(7, 7);

        var response = handler.handleRequest(request, context);

        assertEquals(0, response.totalItemsScanned());
    }
}
