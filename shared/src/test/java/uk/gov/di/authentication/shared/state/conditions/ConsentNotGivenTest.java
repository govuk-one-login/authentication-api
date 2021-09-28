package uk.gov.di.authentication.shared.state.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConsentNotGivenTest {

    private final ConsentNotGiven condition = new ConsentNotGiven();
    private ClientRegistry client = mock(ClientRegistry.class);
    private ClientSession clientSession = mock(ClientSession.class);
    private static final String CLIENT_ID = "test-client";
    private static final String TIME = LocalDateTime.now(ZoneId.of("UTC")).toString();

    @Test
    public void shouldReturnFalseIfClaimsInAuthRequestAreInUserProfileClaims() {
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        UserProfile userProfile = mock(UserProfile.class);
        when(userProfile.getClientConsent())
                .thenReturn(Collections.singletonList(new ClientConsent(CLIENT_ID, claims, TIME)));
        when(client.getClientID()).thenReturn(CLIENT_ID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
        UserContext userContext =
                UserContext.builder(mock(Session.class))
                        .withUserProfile(userProfile)
                        .withClientSession(clientSession)
                        .withClient(client)
                        .build();

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    public void shouldReturnFalseIfAllUserProfileClaimsContainsAllAuthRequestClaimsAndExtras() {
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        UserProfile userProfile = mock(UserProfile.class);
        when(client.getClientID()).thenReturn(CLIENT_ID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
        UserContext userContext =
                UserContext.builder(mock(Session.class))
                        .withUserProfile(userProfile)
                        .withClientSession(clientSession)
                        .withClient(client)
                        .build();

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnTrueWhenConsentInUserProfileIsEmpty() {
        Scope authRequestScopes = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);
        UserProfile userProfile = mock(UserProfile.class);
        when(client.getClientID()).thenReturn(CLIENT_ID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                authRequestScopes,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
        UserContext userContext =
                UserContext.builder(mock(Session.class))
                        .withUserProfile(userProfile)
                        .withClientSession(clientSession)
                        .withClient(client)
                        .build();

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    public void shouldReturnTrueIfAllClaimsInAuthRequestAreNotInUserProfileClaims() {
        Scope authRequestScopes =
                new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        UserProfile userProfile = mock(UserProfile.class);
        when(userProfile.getClientConsent())
                .thenReturn(Collections.singletonList(new ClientConsent(CLIENT_ID, claims, TIME)));
        when(client.getClientID()).thenReturn(CLIENT_ID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                authRequestScopes,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
        UserContext userContext =
                UserContext.builder(mock(Session.class))
                        .withUserProfile(userProfile)
                        .withClientSession(clientSession)
                        .withClient(client)
                        .build();

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }
}
