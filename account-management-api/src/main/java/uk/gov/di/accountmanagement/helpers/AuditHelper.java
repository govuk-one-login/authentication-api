package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuditHelper {

    private static final Logger LOG = LogManager.getLogger(AuditHelper.class);
    public static final String TXMA_ENCODED_HEADER_NAME = "txma-audit-encoded";
    public static final String ERROR_BUILDING_AUDIT_CONTEXT = "Error building audit context";

    public static final AuditService.MetadataPair ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR =
            pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.getValue());

    private AuditHelper() {}

    public static Optional<String> getTxmaAuditEncoded(Map<String, String> headers) {
        String txmaEncodedValue =
                RequestHeaderHelper.getHeaderValueFromHeaders(
                        headers, TXMA_ENCODED_HEADER_NAME, false);
        if (txmaEncodedValue != null && !txmaEncodedValue.isEmpty()) {
            return Optional.of(txmaEncodedValue);
        } else {
            LOG.warn("Audit header field value cannot be empty");
            return Optional.empty();
        }
    }

    public static Result<ErrorResponse, AuditContext> accountManagementAuditContextWithMetadata(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile) {
        return accountManagementAuditContextWithMetadata(
                configurationService,
                dynamoService,
                input,
                userProfile,
                List.of(ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR));
    }

    public static Result<ErrorResponse, AuditContext> accountManagementAuditContext(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile) {
        return accountManagementAuditContextWithMetadata(
                configurationService, dynamoService, input, userProfile, List.of());
    }

    public static Result<ErrorResponse, AuditContext> accountManagementAuditContextWithMetadata(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            List<AuditService.MetadataPair> pairsInContext) {
        try {
            return Result.success(
                    new AuditContext(
                            input.getRequestContext()
                                    .getAuthorizer()
                                    .getOrDefault(ATTRIBUTE_CLIENT_ID, AuditService.UNKNOWN)
                                    .toString(),
                            ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders()),
                            RequestHeaderHelper.getHeaderValueOrElse(
                                    input.getHeaders(), SESSION_ID_HEADER, ""),
                            ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                            userProfile,
                                            configurationService.getInternalSectorUri(),
                                            dynamoService)
                                    .getValue(),
                            userProfile.getEmail(),
                            IpAddressHelper.extractIpAddress(input),
                            null,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            getTxmaAuditEncoded(input.getHeaders()),
                            pairsInContext));
        } catch (Exception e) {
            LOG.error(ERROR_BUILDING_AUDIT_CONTEXT, e);
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }
    }

    public static Result<ErrorResponse, Void> sendAuditEvent(
            AccountManagementAuditableEvent auditEvent,
            AuditContext auditContext,
            AuditService auditService,
            Logger logger) {
        try {
            auditService.submitAuditEvent(auditEvent, auditContext, AUDIT_EVENT_COMPONENT_ID_HOME);
        } catch (Exception e) {
            logger.error("Error submitting audit event", e);
            return Result.failure(ErrorResponse.FAILED_TO_RAISE_AUDIT_EVENT);
        }

        return Result.success(null);
    }

    public static Result<ErrorResponse, Void> sendAuditEvent(
            AccountManagementAuditableEvent auditEvent,
            AuditContext auditContext,
            AuditService auditService,
            Logger logger,
            List<AuditService.MetadataPair> metadataPairs) {
        try {
            auditService.submitAuditEvent(
                    auditEvent,
                    auditContext,
                    AUDIT_EVENT_COMPONENT_ID_HOME,
                    metadataPairs.toArray(new AuditService.MetadataPair[0]));
        } catch (Exception e) {
            logger.error("Error submitting audit event", e);
            return Result.failure(ErrorResponse.FAILED_TO_RAISE_AUDIT_EVENT);
        }

        return Result.success(null);
    }
}
