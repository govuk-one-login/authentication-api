package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.NoSuchElementException;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.WarmerHelper.isWarming;

public class StartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartHandler.class);
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
                        new DynamoService(configurationService));
        this.configurationService = configurationService;
    }

    public StartHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return isWarming(input)
                .orElseGet(
                        () -> {
                            LOG.info("Start request received");
                            var session =
                                    sessionService.getSessionFromRequestHeaders(input.getHeaders());
                            if (session.isEmpty()) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1000);
                            } else {
                                attachSessionIdToLogs(session.get());
                                LOG.info("Start session retrieved");
                            }

                            var clientSession =
                                    clientSessionService.getClientSessionFromRequestHeaders(
                                            input.getHeaders());

                            if (clientSession.isEmpty()) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1018);
                            }
                            try {
                                var userContext =
                                        startService.buildUserContext(
                                                session.get(), clientSession.get());
                                var clientStartInfo =
                                        startService.buildClientStartInfo(userContext);

                                var cookieConsent =
                                        startService.getCookieConsentValue(
                                                userContext
                                                        .getClientSession()
                                                        .getAuthRequestParams(),
                                                userContext.getClient().get().getClientID());
                                var gaTrackingId =
                                        startService.getGATrackingId(
                                                userContext
                                                        .getClientSession()
                                                        .getAuthRequestParams());
                                var userStartInfo =
                                        startService.buildUserStartInfo(
                                                userContext,
                                                cookieConsent,
                                                gaTrackingId,
                                                configurationService.isIdentityEnabled());
                                if (userStartInfo.isDocCheckingAppUser()) {
                                    var docAppSubjectId =
                                            ClientSubjectHelper.calculatePairwiseIdentifier(
                                                    new Subject().getValue(),
                                                    configurationService.getDocAppDomain(),
                                                    SaltHelper.generateNewSalt());
                                    var clientSessionId =
                                            getHeaderValueFromHeaders(
                                                    input.getHeaders(),
                                                    CLIENT_SESSION_ID_HEADER,
                                                    configurationService
                                                            .getHeadersCaseInsensitive());
                                    clientSessionService.saveClientSession(
                                            clientSessionId,
                                            clientSession
                                                    .get()
                                                    .setDocAppSubjectId(
                                                            new Subject(docAppSubjectId)));
                                    LOG.info(
                                            "Subject saved to ClientSession for DocCheckingAppUser");
                                }

                                var startResponse =
                                        new StartResponse(userStartInfo, clientStartInfo);

                                auditService.submitAuditEvent(
                                        FrontendAuditableEvent.START_INFO_FOUND,
                                        context.getAwsRequestId(),
                                        session.get().getSessionId(),
                                        userContext.getClient().get().getClientID(),
                                        AuditService.UNKNOWN,
                                        userContext
                                                .getUserProfile()
                                                .map(UserProfile::getEmail)
                                                .orElse(AuditService.UNKNOWN),
                                        IpAddressHelper.extractIpAddress(input),
                                        AuditService.UNKNOWN,
                                        PersistentIdHelper.extractPersistentIdFromHeaders(
                                                input.getHeaders()));

                                return generateApiGatewayProxyResponse(200, startResponse);

                            } catch (JsonException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1001);
                            } catch (NoSuchElementException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1015);
                            } catch (ParseException e) {
                                return generateApiGatewayProxyErrorResponse(
                                        400, ErrorResponse.ERROR_1038);
                            }
                        });
    }
}
