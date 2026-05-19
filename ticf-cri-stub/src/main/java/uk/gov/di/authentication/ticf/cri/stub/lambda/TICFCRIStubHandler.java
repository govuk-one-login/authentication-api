package uk.gov.di.authentication.ticf.cri.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.entity.ExternalTICFCRIRequest;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.ticf.cri.stub.lambda.entity.TICFCRIStubResponse;

import java.util.List;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class TICFCRIStubHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(TICFCRIStubHandler.class);

    private static final String REQUEST_ID = "request-id";

    private final Json objectMapper = SerializationService.getInstance();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var request = objectMapper.readValue(input.getBody(), ExternalTICFCRIRequest.class);
            LOG.info(
                    "TICF Request - govuk_signin_journey_id: {}, vtr: {}, authenticated: {}, initial_registration: {}, password_reset: {}, 2fa_reset: {}, 2fa_method: {}",
                    request.govukSigninJourneyId(),
                    request.vtr(),
                    request.authenticated(),
                    request.initialRegistration(),
                    request.passwordReset(),
                    request.mfaReset(),
                    request.mfaMethod());
        } catch (Json.JsonException e) {
            LOG.error("Invalid ExternalTICFCRIRequest", e.getMessage());
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
