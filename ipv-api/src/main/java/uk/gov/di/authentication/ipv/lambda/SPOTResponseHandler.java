package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.Optional;

public class SPOTResponseHandler implements RequestHandler<SNSEvent, Object> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoSpotService dynamoSpotService;

    private static final Logger LOG = LogManager.getLogger(SPOTResponseHandler.class);

    public SPOTResponseHandler() {
        this(ConfigurationService.getInstance());
    }

    public SPOTResponseHandler(ConfigurationService configurationService) {
        this.dynamoSpotService = new DynamoSpotService(configurationService);
    }

    public SPOTResponseHandler(DynamoSpotService dynamoSpotService) {
        this.dynamoSpotService = dynamoSpotService;
    }

    @Override
    public Object handleRequest(SNSEvent input, Context context) {
        input.getRecords().stream()
                .map(SNSEvent.SNSRecord::getSNS)
                .map(SNSEvent.SNS::getMessage)
                .map(this::processSPOTResponse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .forEach(this::writeToDynamo);

        return null;
    }

    private Optional<SPOTResponse> processSPOTResponse(String message) {
        try {
            return Optional.of(objectMapper.readValue(message, SPOTResponse.class));
        } catch (JsonProcessingException e) {
            LOG.error("Unable to deserialize SPOT response");
            return Optional.empty();
        }
    }

    private void writeToDynamo(SPOTResponse spotResponse) {
        dynamoSpotService.addSpotResponse(
                spotResponse.getPairwiseIdentifier(), spotResponse.getSerializedCredential());
    }
}
