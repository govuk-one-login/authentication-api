package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class UpdateTokensWithTtlHandlerTest {

    @Mock private OrchAccessTokenService orchAccessTokenService;

    @Mock private Context context;

    private UpdateTokensWithTtlHandler handler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        handler = new UpdateTokensWithTtlHandler(orchAccessTokenService);
    }

    @ParameterizedTest
    @NullSource
    void shouldUseDefaultParametersWithNullInput(Object input) {
        var result = handler.handleRequest(input, context);

        assertEquals("Finished", result);
        verify(orchAccessTokenService)
                .processAccessTokensWithoutTtlInBatches(eq(1000), eq(1), eq(1000), any(), any());
    }

    @Test
    void shouldUseDefaultParametersWithEmptyInput() {
        var result = handler.handleRequest(Map.of(), context);

        assertEquals("Finished", result);
        verify(orchAccessTokenService)
                .processAccessTokensWithoutTtlInBatches(eq(1000), eq(1), eq(1000), any(), any());
    }

    @Test
    void shouldUseCustomParameters() {
        var input = Map.of("readBatchSize", 500, "totalSegments", 4, "maxTokens", 10);
        handler.handleRequest(input, context);

        verify(orchAccessTokenService)
                .processAccessTokensWithoutTtlInBatches(eq(500), eq(4), eq(10), any(), any());
    }

    @Test
    void shouldProcessBatchInWriteSubBatches() {
        var input = Map.of("writeBatchSize", 3);

        ArgumentCaptor<Consumer<List<OrchAccessTokenItem>>> consumerCaptor =
                ArgumentCaptor.forClass(Consumer.class);

        handler.handleRequest(input, context);
        verify(orchAccessTokenService)
                .processAccessTokensWithoutTtlInBatches(
                        eq(1000), eq(1), eq(1000), any(), consumerCaptor.capture());

        var testBatch =
                List.of(
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem(),
                        new OrchAccessTokenItem());
        // Execute the captured consumer with the test batch
        consumerCaptor.getValue().accept(testBatch);

        verify(orchAccessTokenService, times(3)).updateAccessTokensTtlToNow(any());
    }
}
