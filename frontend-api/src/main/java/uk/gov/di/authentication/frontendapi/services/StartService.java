package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.shared.conditions.ConsentHelper;
import uk.gov.di.authentication.shared.conditions.DocAppUserHelper;
import uk.gov.di.authentication.shared.conditions.IdentityHelper;
import uk.gov.di.authentication.shared.conditions.UpliftHelper;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.RequestParameters.GA;

public class StartService {

    private final ClientService clientService;
    private final DynamoService dynamoService;
    private static final String CLIENT_ID_PARAM = "client_id";
    public static final String COOKIE_CONSENT_ACCEPT = "accept";
    public static final String COOKIE_CONSENT_REJECT = "reject";
    public static final String COOKIE_CONSENT_NOT_ENGAGED = "not-engaged";
    private static final Logger LOG = LogManager.getLogger(StartService.class);

    public StartService(ClientService clientService, DynamoService dynamoService) {
        this.clientService = clientService;
        this.dynamoService = dynamoService;
    }

    public UserContext buildUserContext(Session session, ClientSession clientSession) {
        var builder = UserContext.builder(session).withClientSession(clientSession);
        UserContext userContext;
        try {
            var clientId =
                    clientSession.getAuthRequestParams().get(CLIENT_ID_PARAM).stream()
                            .findFirst()
                            .orElseThrow();
            var clientRegistry = clientService.getClient(clientId).orElseThrow();
            Optional.of(session)
                    .map(Session::getEmailAddress)
                    .flatMap(dynamoService::getUserProfileByEmailMaybe)
                    .ifPresent(builder::withUserProfile);
            userContext = builder.withClient(clientRegistry).build();
        } catch (NoSuchElementException e) {
            LOG.error("Error creating UserContext");
            throw new RuntimeException("Error when creating UserContext", e);
        }
        return userContext;
    }

    public ClientStartInfo buildClientStartInfo(UserContext userContext) throws ParseException {
        List<String> scopes;
        URI redirectURI;
        try {
            var authenticationRequest =
                    AuthenticationRequest.parse(
                            userContext.getClientSession().getAuthRequestParams());
            if (Objects.nonNull(authenticationRequest.getRequestObject())) {
                var claimSet = authenticationRequest.getRequestObject().getJWTClaimsSet();
                scopes = Scope.parse((String) claimSet.getClaim("scope")).toStringList();
                redirectURI = URI.create((String) claimSet.getClaim("redirect_uri"));
            } else {
                scopes = authenticationRequest.getScope().toStringList();
                redirectURI = authenticationRequest.getRedirectionURI();
            }
        } catch (ParseException e) {
            throw new ParseException("Unable to parse authentication request");
        } catch (java.text.ParseException e) {
            throw new RuntimeException("Unable to parse claims in request object");
        }
        var clientRegistry = userContext.getClient().orElseThrow();
        var clientInfo =
                new ClientStartInfo(
                        clientRegistry.getClientName(),
                        scopes,
                        clientRegistry.getServiceType(),
                        clientRegistry.isCookieConsentShared(),
                        redirectURI);
        LOG.info(
                "Found ClientStartInfo for ClientName: {} Scopes: {} ServiceType: {}",
                clientRegistry.getClientName(),
                scopes,
                clientRegistry.getServiceType());

        return clientInfo;
    }

    public UserStartInfo buildUserStartInfo(
            UserContext userContext, String cookieConsent, String gaTrackingId) {
        var uplift = false;
        var identityRequired = false;
        var consentRequired = false;
        var docCheckingAppUser = DocAppUserHelper.isDocCheckingAppUser(userContext);
        if (Boolean.FALSE.equals(docCheckingAppUser)) {
            consentRequired = ConsentHelper.userHasNotGivenConsent(userContext);
            uplift = UpliftHelper.upliftRequired(userContext);
            identityRequired =
                    IdentityHelper.identityRequired(
                            userContext.getClientSession().getAuthRequestParams());
        }
        LOG.info(
                "Found UserStartInfo for Authenticated: {} ConsentRequired: {} UpliftRequired: {} IdentityRequired: {}. CookieConsent: {}. GATrackingId: {}. DocCheckingAppUser: {}",
                userContext.getSession().isAuthenticated(),
                consentRequired,
                uplift,
                identityRequired,
                cookieConsent,
                gaTrackingId,
                docCheckingAppUser);

        return new UserStartInfo(
                consentRequired,
                uplift,
                identityRequired,
                userContext.getSession().isAuthenticated(),
                cookieConsent,
                gaTrackingId,
                docCheckingAppUser);
    }

    public String getGATrackingId(Map<String, List<String>> authRequestParameters) {
        if (authRequestParameters.containsKey(GA)) {
            String gaId = authRequestParameters.get(GA).get(0);
            LOG.info("GA value present in request {}", gaId);
            return gaId;
        }
        return null;
    }

    public String getCookieConsentValue(
            Map<String, List<String>> authRequestParameters, String clientID) {
        try {
            if (validCookieConsentValueIsPresent(authRequestParameters)
                    && isClientCookieConsentShared(clientID)) {
                LOG.info("Sharing cookie_consent");
                return authRequestParameters.get(COOKIE_CONSENT).get(0);
            }
            return null;
        } catch (ClientNotFoundException e) {
            throw new RuntimeException("Client not found", e);
        }
    }

    private boolean isClientCookieConsentShared(String clientID) throws ClientNotFoundException {
        return clientService
                .getClient(clientID)
                .map(ClientRegistry::isCookieConsentShared)
                .orElseThrow(() -> new ClientNotFoundException(clientID));
    }

    private boolean validCookieConsentValueIsPresent(
            Map<String, List<String>> authRequestParameters) {
        return authRequestParameters.containsKey(COOKIE_CONSENT)
                && !authRequestParameters.get(COOKIE_CONSENT).isEmpty()
                && authRequestParameters.get(COOKIE_CONSENT).get(0) != null
                && List.of(COOKIE_CONSENT_ACCEPT, COOKIE_CONSENT_REJECT, COOKIE_CONSENT_NOT_ENGAGED)
                        .contains(authRequestParameters.get(COOKIE_CONSENT).get(0));
    }
}
