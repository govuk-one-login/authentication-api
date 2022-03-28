package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import static java.util.Collections.singletonList;
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
    void shouldWriteToDynamoForSuccesssfulSPOTResponse() {
        String json =
                "{\"sub\":\"some-pairwise-identifier\",\"status\":\"OK\","
                        + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"random-searalized-credential\"}}";

        handler.handleRequest(generateSQSEvent(json), null);

        verify(dynamoSpotService)
                .addSpotResponse("some-pairwise-identifier", "random-searalized-credential");
    }

    @Test
    void shouldNotWriteToDynamoWhenLambdaReceivedInvalidSPOTResponse() {
        handler.handleRequest(generateSQSEvent("invalid-payload"), null);

        verifyNoInteractions(dynamoSpotService);
    }

    @Test
    void shouldNotWriteToDynamoWhenSPOTResponseStatusIsNotOK() {
        String json =
                "{\"sub\":\"some-pairwise-identifier\",\"status\":\"OTHER\","
                        + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"random-searalized-credential\"}}";

        handler.handleRequest(generateSQSEvent(json), null);

        verifyNoInteractions(dynamoSpotService);
    }

    @Test
    void shouldNotWriteToDynamoWhenStatusIsOKButNoCredentialIsPresent() {
        String json = "{\"sub\":\"some-pairwise-identifier\",\"status\":\"OK\"," + "\"claims\":{}}";

        handler.handleRequest(generateSQSEvent(json), null);

        verifyNoInteractions(dynamoSpotService);
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSEvent.SQSMessage sqsMessage = new SQSEvent.SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
