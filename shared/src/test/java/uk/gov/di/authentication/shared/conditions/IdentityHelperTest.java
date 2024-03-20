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

import static java.util.Objects.nonNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class IdentityHelperTest {
    @Test
    void shouldReturnFalseIfIdentityNotRequired() {
        assertFalse(IdentityHelper.identityRequired(false, true, true));
    }

    @Test
    void shouldReturnTrueIfIdentityRequired() {
        assertTrue(IdentityHelper.identityRequired(true, true, true));
    }

    @Test
    void shouldReturnFalseIfIdentityIsNotEnabled() {
        assertFalse(IdentityHelper.identityRequired(true, true, false));
    }

    @Test
    void shouldReturnFalseWhenRPDoesNotSupportIdentityVerification() {
        assertFalse(IdentityHelper.identityRequired(true, false, true));
    }
}
