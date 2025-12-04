package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.ipv.entity.SPOTStatus;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.NoSuchElementException;

import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

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
                attachTraceId();
                var spotResponse = objectMapper.readValue(msg.getBody(), SPOTResponse.class);
                var logIds = spotResponse.getLogIds();

                attachSessionIdToLogs(logIds.getSessionId());
                attachLogFieldToLogs(PERSISTENT_SESSION_ID, logIds.getPersistentSessionId());
                attachLogFieldToLogs(CLIENT_ID, logIds.getClientId());
                attachLogFieldToLogs(CLIENT_SESSION_ID, logIds.getClientSessionId());
                attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, logIds.getClientSessionId());

                var user =
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(logIds.getClientSessionId())
                                .withSessionId(logIds.getSessionId())
                                .withPersistentSessionId(logIds.getPersistentSessionId());

                LOG.info(
                        "is clientSessionId defined: {}",
                        logIds.getClientSessionId() != null
                                && !logIds.getClientSessionId().isBlank());

                if (spotResponse.getStatus().equals(SPOTStatus.ACCEPTED)) {
                    LOG.info(
                            "SPOTResponse Status is {}. Sending audit event and adding CoreIdentityJWT to Dynamo",
                            spotResponse.getStatus());
                    auditService.submitAuditEvent(
                            IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED, logIds.getClientId(), user);
                    LOG.info("Finished sending audit event");
                    dynamoIdentityService.addCoreIdentityJWT(
                            logIds.getClientSessionId(),
                            spotResponse.getSub(),
                            spotResponse.getClaims().values().stream()
                                    .map(Object::toString)
                                    .findFirst()
                                    .orElseThrow());
                    LOG.info("Finished adding CoreIdentityJWT to Dynamo");
                    return null;
                } else {
                    LOG.warn(
                            "SPOTResponse Status is {}. Rejection reason: {}. Deleting Identity Credential.",
                            spotResponse.getStatus(),
                            spotResponse.getReason());
                    auditService.submitAuditEvent(
                            IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED, logIds.getClientId(), user);
                    dynamoIdentityService.deleteIdentityCredentials(logIds.getClientSessionId());
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
}
