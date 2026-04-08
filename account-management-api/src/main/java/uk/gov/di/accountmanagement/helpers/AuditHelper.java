package uk.gov.di.accountmanagement.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_NOTIFICATION_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.AuthSessionItem.ATTRIBUTE_CLIENT_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class AuditHelper {

    private static final Logger LOG = LogManager.getLogger(AuditHelper.class);
    public static final String TXMA_ENCODED_HEADER_NAME = "txma-audit-encoded";
    public static final String ERROR_BUILDING_AUDIT_CONTEXT = "Error building audit context";

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

    public static Result<ErrorResponse, AuditContext> buildAuditContext(
            ConfigurationService configurationService,
            DynamoService dynamoService,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile) {
        try {
            var metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.getValue())
                    };

            var context =
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
                            List.of(metadataPairs));

            return Result.success(context);
        } catch (Exception e) {
            LOG.error(ERROR_BUILDING_AUDIT_CONTEXT, e);
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }
    }

    public static Result<ErrorResponse, AuditContext> buildAuditContextForMfa(
            AccountManagementAuditableEvent auditEvent,
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MfaMethodCreateRequest mfaMethodCreateRequest,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            Logger logger) {
        try {
            var initialMetadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.getValue())
                    };

            var context =
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
                            List.of(initialMetadataPairs));

            context = enrichAuditContextForMfaMethod(auditEvent, context, mfaMethodCreateRequest);

            return Result.success(context);
        } catch (Exception e) {
            logger.error(ERROR_BUILDING_AUDIT_CONTEXT, e);
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }
    }

    public static Result<ErrorResponse, AuditContext> buildAuditContextForMfaMethod(
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            MFAMethod mfaMethod,
            ConfigurationService configurationService,
            DynamoService dynamoService,
            Logger logger) {
        try {
            var phoneNumber =
                    mfaMethod.getMfaMethodType().equals(MFAMethodType.SMS.name())
                            ? mfaMethod.getDestination()
                            : AuditService.UNKNOWN;

            var metadataPairs =
                    new AuditService.MetadataPair[] {
                        pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_MANAGEMENT.getValue()),
                        pair(AUDIT_EVENT_EXTENSIONS_MFA_TYPE, mfaMethod.getMfaMethodType())
                    };

            var context =
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
                            phoneNumber,
                            PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                            getTxmaAuditEncoded(input.getHeaders()),
                            List.of(metadataPairs));

            return Result.success(context);
        } catch (Exception e) {
            logger.error(ERROR_BUILDING_AUDIT_CONTEXT, e);
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }
    }

    private static AuditContext enrichAuditContextForMfaMethod(
            AccountManagementAuditableEvent auditEvent,
            AuditContext context,
            MfaMethodCreateRequest mfaMethodCreateRequest) {

        if (mfaMethodCreateRequest != null) {
            context =
                    context.withMetadataItem(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_TYPE,
                                            mfaMethodCreateRequest
                                                    .mfaMethod()
                                                    .method()
                                                    .mfaMethodType()
                                                    .toString()))
                            .withMetadataItem(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                            PriorityIdentifier.BACKUP.name().toLowerCase()));

            if (mfaMethodCreateRequest.mfaMethod().method()
                    instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
                context = context.withPhoneNumber(requestSmsMfaDetail.phoneNumber());
                context =
                        context.withMetadataItem(
                                pair(
                                        AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                        PhoneNumberHelper.getCountry(
                                                requestSmsMfaDetail.phoneNumber())));

                if (auditEvent.equals(AccountManagementAuditableEvent.AUTH_CODE_VERIFIED)
                        && requestSmsMfaDetail.otp() != null) {
                    context =
                            context.withMetadataItem(
                                            pair(
                                                    AUDIT_EVENT_EXTENSIONS_MFA_CODE_ENTERED,
                                                    requestSmsMfaDetail.otp()))
                                    .withMetadataItem(
                                            pair(
                                                    AUDIT_EVENT_EXTENSIONS_NOTIFICATION_TYPE,
                                                    MFA_SMS.name()));
                }
            }

            if (auditEvent.equals(AccountManagementAuditableEvent.AUTH_CODE_VERIFIED)) {
                context =
                        context.withMetadataItem(
                                        pair(AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY, "false"))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                                ACCOUNT_MANAGEMENT.name()));
            }
        }

        return context;
    }

    public static Result<ErrorResponse, AuditContext> updateAuditContextForFailedMFACreation(
            UserProfile userProfile,
            AuditContext auditContext,
            MFAMethodsService mfaMethodsService,
            Logger logger) {

        var maybeMfaMethods = mfaMethodsService.getMfaMethods(userProfile.getEmail());

        if (maybeMfaMethods.isFailure()) {
            logger.error("No MFA methods found for user");
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }

        var mfaMethods = maybeMfaMethods.getSuccess();

        var defaultMfaMethod =
                mfaMethods.stream()
                        .filter(
                                method ->
                                        method.getPriority()
                                                .equalsIgnoreCase(
                                                        PriorityIdentifier.DEFAULT.name()))
                        .findFirst();

        if (defaultMfaMethod.isEmpty()) {
            logger.error("No default MFA method found for user");
            return Result.failure(UNEXPECTED_ACCT_MGMT_ERROR);
        }

        if (defaultMfaMethod.get().getMfaMethodType().equalsIgnoreCase(MFAMethodType.SMS.name())) {
            auditContext = auditContext.withPhoneNumber(defaultMfaMethod.get().getDestination());
        }

        auditContext =
                auditContext.withMetadataItem(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_TYPE,
                                defaultMfaMethod.get().getMfaMethodType()));
        auditContext =
                auditContext.withMetadataItem(
                        pair(
                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                PriorityIdentifier.DEFAULT.name().toLowerCase()));
        return Result.success(auditContext);
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
}
