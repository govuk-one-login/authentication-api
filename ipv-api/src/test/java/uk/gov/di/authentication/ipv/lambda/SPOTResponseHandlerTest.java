package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class SPOTResponseHandlerTest {

    private SPOTResponseHandler handler;
    private final DynamoSpotService dynamoSpotService = mock(DynamoSpotService.class);

    @BeforeEach
    void setup() {
        handler = new SPOTResponseHandler(dynamoSpotService);
    }

    @Test
    void shouldWriteToDynamoForSuccesssfulSPOTResponse() throws JsonProcessingException {
        var spotResponse =
                new SPOTResponse("this-is-a-searalized-credential", "some-pairwise-identifier");
        var searlizedSpotResponse = new ObjectMapper().writeValueAsString(spotResponse);

        handler.handleRequest(inputEvent(searlizedSpotResponse), null);

        verify(dynamoSpotService)
                .addSpotResponse("some-pairwise-identifier", "this-is-a-searalized-credential");
    }

    @Test
    void shouldNotWriteToDynamoWhenLambdaReceivedInvalidSPOTResponse() {
        handler.handleRequest(inputEvent("invalid-payload"), null);

        verifyNoInteractions(dynamoSpotService);
    }

    private SNSEvent inputEvent(String payload) {
        return Optional.of(payload)
                .map(new SNSEvent.SNS()::withMessage)
                .map(new SNSEvent.SNSRecord()::withSns)
                .map(List::of)
                .map(new SNSEvent()::withRecords)
                .get();
    }
}
