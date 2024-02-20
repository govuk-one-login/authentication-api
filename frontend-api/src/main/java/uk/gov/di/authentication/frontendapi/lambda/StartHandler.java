package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.Features;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.DocAppSubjectIdHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.UNKNOWN;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.PersistentIdHelper.extractPersistentIdFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class StartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartHandler.class);

    protected static final String REAUTHENTICATE_HEADER = "Reauthenticate";
    private final ClientSessionService clientSessionService;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final StartService startService;
    private final ConfigurationService configurationService;

    public StartHandler(
            ClientSessionService clientSessionService,
            SessionService sessionService,
            AuditService auditService,
            StartService startService,
            ConfigurationService configurationService) {
        this.clientSessionService = clientSessionService;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.startService = startService;
        this.configurationService = configurationService;
    }

    public StartHandler(ConfigurationService configurationService) {
        this.clientSessionService = new ClientSessionService(configurationService);
        this.sessionService = new SessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.startService =
                new StartService(
                        new DynamoClientService(configurationService),
                        new DynamoService(configurationService),
                        sessionService);
        this.configurationService = configurationService;
    }

    public StartHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        LOG.info("Start request received");
        var session = sessionService.getSessionFromRequestHeaders(input.getHeaders()).orElse(null);
        if (Objects.isNull(session)) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1000);
        } else {
            attachSessionIdToLogs(session);
            LOG.info("Start session retrieved");
        }
        attachLogFieldToLogs(
                PERSISTENT_SESSION_ID, extractPersistentIdFromHeaders(input.getHeaders()));

        var clientSession =
                clientSessionService.getClientSessionFromRequestHeaders(input.getHeaders());

        if (clientSession.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1018);
        }
        try {
            session =
                    startService.validateSession(
                            session,
                            getHeaderValueFromHeaders(
                                    input.getHeaders(),
                                    CLIENT_SESSION_ID_HEADER,
                                    configurationService.getHeadersCaseInsensitive()));
            var userContext = startService.buildUserContext(session, clientSession.get());

            attachLogFieldToLogs(
                    CLIENT_ID,
                    userContext.getClient().map(ClientRegistry::getClientID).orElse(UNKNOWN));
            var clientStartInfo = startService.buildClientStartInfo(userContext);

            var cookieConsent =
                    startService.getCookieConsentValue(
                            userContext.getClientSession().getAuthRequestParams(),
                            userContext.getClient().get().getClientID());
            var gaTrackingId =
                    startService.getGATrackingId(
                            userContext.getClientSession().getAuthRequestParams());
            var reauthenticateHeader =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            REAUTHENTICATE_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            var reauthenticate =
                    reauthenticateHeader != null && reauthenticateHeader.equals("true");
            LOG.info(
                    "reauthenticateHeader: {} reauthenticate: {}",
                    reauthenticateHeader,
                    reauthenticate);
            var userStartInfo =
                    startService.buildUserStartInfo(
                            userContext,
                            cookieConsent,
                            gaTrackingId,
                            configurationService.isIdentityEnabled(),
                            reauthenticate);
            var clientSessionId =
                    getHeaderValueFromHeaders(
                            input.getHeaders(),
                            CLIENT_SESSION_ID_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            if (userStartInfo.isDocCheckingAppUser()) {
                var docAppSubjectId =
                        DocAppSubjectIdHelper.calculateDocAppSubjectId(
                                userContext.getClientSession().getAuthRequestParams(),
                                configurationService.isCustomDocAppClaimEnabled(),
                                configurationService.getDocAppDomain());
                clientSessionService.saveClientSession(
                        clientSessionId, clientSession.get().setDocAppSubjectId(docAppSubjectId));
                LOG.info("Subject saved to ClientSession for DocCheckingAppUser");
            }

            StartResponse startResponse;
            if (configurationService.isExtendedFeatureFlagsEnabled()) {
                Features features = startService.getSessionFeatures();
                LOG.info("Extended feature flags enabled: {}", features);
                startResponse = new StartResponse(userStartInfo, clientStartInfo, features);
            } else {
                startResponse = new StartResponse(userStartInfo, clientStartInfo);
            }

            String internalSubjectId = AuditService.UNKNOWN;
            String internalCommonSubjectIdentifier = AuditService.UNKNOWN;
            if (userStartInfo.isAuthenticated()) {
                LOG.info(
                        "User is authenticated. Setting internalCommonSubjectId and internalSubjectId");
                internalCommonSubjectIdentifier =
                        Optional.ofNullable(session.getInternalCommonSubjectIdentifier())
                                .orElse(AuditService.UNKNOWN);
                internalSubjectId =
                        userContext
                                .getUserProfile()
                                .map(UserProfile::getSubjectID)
                                .orElse(AuditService.UNKNOWN);
            }
            auditService.submitAuditEvent(
                    FrontendAuditableEvent.START_INFO_FOUND,
                    clientSessionId,
                    session.getSessionId(),
                    userContext.getClient().get().getClientID(),
                    internalCommonSubjectIdentifier,
                    userContext
                            .getUserProfile()
                            .map(UserProfile::getEmail)
                            .orElse(AuditService.UNKNOWN),
                    IpAddressHelper.extractIpAddress(input),
                    AuditService.UNKNOWN,
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()),
                    pair("internalSubjectId", internalSubjectId));

            return generateApiGatewayProxyResponse(200, startResponse);

        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        } catch (NoSuchElementException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1015);
        } catch (ParseException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1038);
        }
    }
}
