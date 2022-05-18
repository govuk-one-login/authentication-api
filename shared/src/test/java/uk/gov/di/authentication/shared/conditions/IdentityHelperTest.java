package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class IdentityHelperTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);

    @Test
    void shouldReturnFalseWhenNoLevelOfConfidenceIsPresentInAuthRequest() {
        var authRequest = createAuthRequest("Cl.Cm");

        assertFalse(IdentityHelper.identityRequired(authRequest.toParameters(), true));
    }

    @Test
    void shouldReturnTrueIfLevelOfConfidenceGreaterThanP0IsPresentInAuthRequest() {
        var authRequest = createAuthRequest("P2.Cl.Cm");

        assertTrue(IdentityHelper.identityRequired(authRequest.toParameters(), true));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        var authRequest = createAuthRequest("P2.Cl.Cm");

        assertFalse(IdentityHelper.identityRequired(authRequest.toParameters(), false));
    }

    private AuthenticationRequest createAuthRequest(String vtrValue) {
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE), SCOPES, CLIENT_ID, REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .customParameter("vtr", jsonArrayOf(vtrValue))
                .build();
    }
}
