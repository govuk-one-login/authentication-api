package uk.gov.di.authentication.ticf.cri.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.entity.TICFCRIRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.ticf.cri.stub.lambda.entity.TICFCRIStubResponse;

import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class TICFCRIStubHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var request = objectMapper.readValue(input.getBody(), TICFCRIRequest.class);
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
        String testInternalPairwiseId = "urn:fdc:gov.uk:2022:test";
        String testJourneyId = "44444444-4444-4444-4444-444444444444";
        List<String> testCi = List.of("D03", "F01");
        TICFCRIStubResponse.Intervention testIntervention =
                new TICFCRIStubResponse.Intervention("01", "01");
        try {
            return generateApiGatewayProxyResponse(
                    200,
                    new TICFCRIStubResponse(
                            testIntervention, testInternalPairwiseId, testJourneyId, testCi));
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
    }
}
