package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Optional;

class SPOTResponseHandlerTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SPOTResponseHandlerTest.class);

    private final SPOTResponseHandler handler = new SPOTResponseHandler();

    @BeforeEach
    void setup() {

    }


    @Test
    void shouldWriteToDynamoForSuccesssfulSPOTResponse() throws JsonProcessingException {
        var spotResponse =
                new SPOTResponse("this-is-a-searalized-credential", "some-pairwise-identifier");
        var searlizedSpotResponse = new ObjectMapper().writeValueAsString(spotResponse);

        handler.handleRequest(inputEvent(searlizedSpotResponse), null);
    }

    @Test
    void shouldNotWriteToDynamoWhenLambdaReceivedInvalidSPOTResponse() {

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
