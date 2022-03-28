package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.ipv.entity.SPOTStatus;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoSpotService;

import java.util.NoSuchElementException;

public class SPOTResponseHandler implements RequestHandler<SQSEvent, Object> {

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
    public Object handleRequest(SQSEvent event, Context context) {
        for (SQSMessage msg : event.getRecords()) {
            try {
                var spotResponse = objectMapper.readValue(msg.getBody(), SPOTResponse.class);
                if (spotResponse.getStatus() != SPOTStatus.OK) {
                    LOG.warn(
                            "SPOTResponse Status is not OK. Actual Status: {}",
                            spotResponse.getStatus());
                    return null;
                }
                dynamoSpotService.addSpotResponse(
                        spotResponse.getSub(),
                        spotResponse.getClaims().values().stream()
                                .map(Object::toString)
                                .findFirst()
                                .orElseThrow());
            } catch (JsonProcessingException e) {
                LOG.error("Unable to deserialize SPOT response from SQS queue");
                return null;
            } catch (NoSuchElementException e) {
                LOG.error("Status is OK but no credential is present in SPOTResponse");
                return null;
            }
        }
        return null;
    }
}
