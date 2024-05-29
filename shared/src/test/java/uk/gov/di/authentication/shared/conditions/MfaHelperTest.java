package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Test;

import java.util.Collections;
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
        Map<String, List<String>> authRequestParams = new HashMap<String, List<String>>();
        authRequestParams.put("vtr", List.of("[\"Cl.Cm\"]"));
        authRequestParams.put("client_id", Collections.singletonList("CLIENT_ID"));
        authRequestParams.put("response_type", Collections.singletonList("code"));
        authRequestParams.put("scope", Collections.singletonList("openid"));
        authRequestParams.put("redirect_uri", Collections.singletonList("REDIRECT_URI"));
        assertTrue(MfaHelper.mfaRequired(authRequestParams));
    }
}
