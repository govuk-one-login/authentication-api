package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;

import java.net.URI;

import static java.util.Objects.nonNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class IdentityHelperTest {
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);


    @Test
    void shouldReturnFalseIfIdentityNotRequired() {
        assertFalse(IdentityHelper.identityRequired(false, null, true, true));
    }

    @Test
    void shouldReturnTrueIfIdentityRequired() {
        assertTrue(IdentityHelper.identityRequired(true, null, true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        assertFalse(IdentityHelper.identityRequired(true, null, true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        assertFalse(IdentityHelper.identityRequired(true, null, false, true));
    }

    @Test
    void shouldFallBackToParsingAuthRequestIfIdentityRequiredIsNull() {
        assertFalse(IdentityHelper.identityRequired(null, createAuthRequest("P0.Cl.Cm").toParameters(), true, true));
        assertTrue(IdentityHelper.identityRequired(null, createAuthRequest("P2.Cl.Cm").toParameters(), true, true));
    }

    private AuthenticationRequest createAuthRequest(String vtrValue) {
        var builder =
                new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        SCOPES,
                        CLIENT_ID,
                        REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce());

        if (nonNull(vtrValue)) builder.customParameter("vtr", jsonArrayOf(vtrValue));
        return builder.build();
    }
}
