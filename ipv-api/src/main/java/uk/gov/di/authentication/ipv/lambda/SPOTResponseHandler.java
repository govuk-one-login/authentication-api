package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.LogIds;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.ipv.entity.SPOTStatus;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class SPOTResponseHandler implements RequestHandler<SQSEvent, Object> {

    private final Json objectMapper = SerializationService.getInstance();
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
        for (SQSMessage msg : event.getRecords()) {
            try {
                ThreadContext.clearMap();
                var spotResponse = objectMapper.readValue(msg.getBody(), SPOTResponse.class);
                attachSessionIdToLogs(spotResponse.getLogIds().getSessionId());
                attachLogFieldToLogs(
                        PERSISTENT_SESSION_ID, spotResponse.getLogIds().getPersistentSessionId());
                attachLogFieldToLogs(CLIENT_ID, spotResponse.getLogIds().getClientId());
                attachLogFieldToLogs(
                        CLIENT_SESSION_ID, spotResponse.getLogIds().getClientSessionId());
                attachLogFieldToLogs(
                        GOVUK_SIGNIN_JOURNEY_ID, spotResponse.getLogIds().getClientSessionId());

                if (spotResponse.getStatus().equals(SPOTStatus.ACCEPTED)) {
                    LOG.info(
                            "SPOTResponse Status is {}. Adding CoreIdentityJWT to Dynamo",
                            spotResponse.getStatus());
                    submitAuditEvent(
                            IPVAuditableEvent.IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED,
                            spotResponse.getLogIds());
                    dynamoIdentityService.addCoreIdentityJWT(
                            spotResponse.getSub(),
                            spotResponse.getClaims().values().stream()
                                    .map(Object::toString)
                                    .findFirst()
                                    .orElseThrow());
                    return null;
                } else {
                    LOG.warn(
                            "SPOTResponse Status is {}. Rejection reason: {}. Deleting Identity Credential.",
                            spotResponse.getStatus(),
                            spotResponse.getReason());
                    submitAuditEvent(
                            IPVAuditableEvent.IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED,
                            spotResponse.getLogIds());
                    dynamoIdentityService.deleteIdentityCredentials(spotResponse.getSub());
                    return null;
                }
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

    private void submitAuditEvent(AuditableEvent auditableEvent, LogIds logIds) {
        auditService.submitAuditEvent(
                auditableEvent,
                logIds.getClientSessionId(),
                logIds.getSessionId(),
                logIds.getClientId(),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                logIds.getPersistentSessionId());
    }
}
