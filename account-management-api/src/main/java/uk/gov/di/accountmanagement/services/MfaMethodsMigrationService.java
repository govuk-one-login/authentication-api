package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MIGRATION_SUCCEEDED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueOrElse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class MfaMethodsMigrationService {
    private final ConfigurationService configurationService;
    private final MFAMethodsService mfaMethodsService;
    private final AuditService auditService;

    public MfaMethodsMigrationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = new MFAMethodsService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    public MfaMethodsMigrationService(
            ConfigurationService configurationService,
            MFAMethodsService mfaMethodsService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.mfaMethodsService = mfaMethodsService;
        this.auditService = auditService;
    }

    public Optional<APIGatewayProxyResponseEvent> migrateMfaCredentialsForUserIfRequired(
            UserProfile userProfile,
            Logger loggerForCallingHandler,
            APIGatewayProxyRequestEvent input,
            MfaDetail mfaMethodType) {
        if (!userProfile.isMfaMethodsMigrated()) {
            Optional<MfaMigrationFailureReason> maybeMfaMigrationFailureReason =
                    mfaMethodsService.migrateMfaCredentialsForUser(userProfile);

            emitMfaMethodMigrationAttemptedAuditEvent(
                    userProfile, input, mfaMethodType, maybeMfaMigrationFailureReason.isEmpty());

            if (maybeMfaMigrationFailureReason.isPresent()) {
                MfaMigrationFailureReason mfaMigrationFailureReason =
                        maybeMfaMigrationFailureReason.get();

                loggerForCallingHandler.warn(
                        "Failed to migrate user's MFA credentials due to {}",
                        mfaMigrationFailureReason);

                return switch (mfaMigrationFailureReason) {
                    case NO_CREDENTIALS_FOUND_FOR_USER -> Optional.of(
                            generateApiGatewayProxyErrorResponse(404, ErrorResponse.ERROR_1056));
                    case UNEXPECTED_ERROR_RETRIEVING_METHODS -> Optional.of(
                            generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1064));
                    case ALREADY_MIGRATED -> Optional.empty();
                };
            } else {
                loggerForCallingHandler.info("MFA Methods migrated for user");
            }
        }

        return Optional.empty();
    }

    private void emitMfaMethodMigrationAttemptedAuditEvent(
            UserProfile userProfile,
            APIGatewayProxyRequestEvent input,
            MfaDetail mfaMethod,
            Boolean migrationSucceeded) {

        var headers = input.getHeaders();

        String sessionId = getHeaderValueOrElse(headers, SESSION_ID_HEADER, "unknown");
        String clientSessionId = ClientSessionIdHelper.extractSessionIdFromHeaders(headers);
        String ipAddress = IpAddressHelper.extractIpAddress(input);
        String persistentSessionId = PersistentIdHelper.extractPersistentIdFromHeaders(headers);
        Map<String, Object> authorizerParams = input.getRequestContext().getAuthorizer();

        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId((String) authorizerParams.get("clientId"))
                        .withEmail(userProfile.getEmail())
                        .withSessionId(sessionId)
                        .withClientSessionId(clientSessionId)
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId)
                        .withSubjectId(input.getPathParameters().get("publicSubjectId"))
                        .withPhoneNumber(userProfile.getPhoneNumber())
                        .withTxmaAuditEncoded(AuditHelper.getTxmaAuditEncoded(input.getHeaders()));

        if (mfaMethod instanceof RequestSmsMfaDetail requestSmsMfaDetail) {
            auditContext =
                    auditContext.withMetadataItem(
                            pair(
                                    AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE,
                                    PhoneNumberHelper.getCountry(
                                            requestSmsMfaDetail.phoneNumber())));
        }

        auditContext =
                auditContext.withMetadataItem(
                        pair(AUDIT_EVENT_EXTENSIONS_MFA_TYPE, mfaMethod.mfaMethodType()));
        auditContext =
                auditContext.withMetadataItem(
                        pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, JourneyType.ACCOUNT_MANAGEMENT));
        auditContext =
                auditContext.withMetadataItem(
                        pair(AUDIT_EVENT_EXTENSIONS_MIGRATION_SUCCEEDED, migrationSucceeded));

        auditService.submitAuditEvent(
                AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED, auditContext);
    }
}
