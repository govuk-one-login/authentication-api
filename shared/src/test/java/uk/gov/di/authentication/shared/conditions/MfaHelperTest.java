package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MfaHelperTest {

    @Test
    void shouldThrowRuntimeExceptionWhenInvalidAuthRequestParamsPassed() {
        Map<String, List<String>> authRequestParams = new HashMap<String, List<String>>();
        assertThrows(RuntimeException.class, () -> MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnTrueWhenVtrParameterIsMediumLevel() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"Cl.Cm\"]");
        assertTrue(MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnFalseWhenVtrParameterIsLowLevel() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"Cl\"]");
        assertFalse(MfaHelper.mfaRequired(authRequestParams));
    }

    @NotNull
    private static Map<String, List<String>> buildAuthRequest(String vtr) {
        return new AuthenticationRequest.Builder(
                        ResponseType.CODE,
                        new Scope("openid"),
                        new ClientID("CLIENT_ID"),
                        URI.create("REDIRECT_URI"))
                .customParameter("vtr", vtr)
                .build()
                .toParameters();
    }
}
