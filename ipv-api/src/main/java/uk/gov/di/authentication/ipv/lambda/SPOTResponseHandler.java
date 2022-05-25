package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.ipv.entity.SPOTStatus;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;

import java.util.NoSuchElementException;

public class SPOTResponseHandler implements RequestHandler<SQSEvent, Object> {

    private final Json objectMapper = Json.jackson();
    private final DynamoIdentityService dynamoIdentityService;
    private final AuditService auditService;

    private static final Logger LOG = LogManager.getLogger(SPOTResponseHandler.class);

    public SPOTResponseHandler() {
        this(ConfigurationService.getInstance());
    }

    public SPOTResponseHandler(ConfigurationService configurationService) {
        this.dynamoIdentityService = new DynamoIdentityService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public SPOTResponseHandler(
            DynamoIdentityService dynamoIdentityService, AuditService auditService) {
        this.dynamoIdentityService = dynamoIdentityService;
        this.auditService = auditService;
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {
        auditService.submitAuditEvent(
                IPVAuditableEvent.SPOT_RESPONSE_RECEIVED,
                context.getAwsRequestId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN);

        for (SQSMessage msg : event.getRecords()) {
            try {
                var spotResponse = objectMapper.readValue(msg.getBody(), SPOTResponse.class);
                if (spotResponse.getStatus() != SPOTStatus.ACCEPTED) {
                    LOG.warn(
                            "SPOTResponse Status is not Accepted. Actual Status: {}",
                            spotResponse.getStatus());
                    return null;
                }
                LOG.info("SPOTResponse Status is Accepted. Adding CoreIdentityJWT to Dynamo");

                dynamoIdentityService.addCoreIdentityJWT(
                        spotResponse.getSub(),
                        spotResponse.getClaims().values().stream()
                                .map(Object::toString)
                                .findFirst()
                                .orElseThrow());
            } catch (JsonException e) {
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
