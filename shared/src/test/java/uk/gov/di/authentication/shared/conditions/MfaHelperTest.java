package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.UserCredentials;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MfaHelperTest {

    public static final String EMAIL = "joe.bloggs@test.com";
    public static final String PASSWORD = "computer-1";
    public static final String UK_MOBILE_NUMBER = "+447234567890";

    private UserCredentials userCredentials;

    @BeforeEach
    void setup() {
        userCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(PASSWORD)
                        .withSubjectID(UK_MOBILE_NUMBER);
    }

    @Test
    void shouldThrowRuntimeExceptionWhenInvalidAuthRequestParamsPassed() {
        Map<String, List<String>> authRequestParams = new HashMap<>();
        assertThrows(RuntimeException.class, () -> MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnTrueWhenVtrParameterIsMediumLevel() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"Cl.Cm\"]");
        assertTrue(MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnTrueWhenVtrParameterIncludesP0() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"P0.Cl.Cm\"]");
        assertTrue(MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldThrowIllegalArgumentExceptionForInvalidVTR() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"Cl.C\"]");
        assertThrows(
                IllegalArgumentException.class, () -> MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnFalseWhenVtrParameterIsLowLevel() {
        Map<String, List<String>> authRequestParams = buildAuthRequest("[\"Cl\"]");
        assertFalse(MfaHelper.mfaRequired(authRequestParams));
    }

    @Test
    void shouldReturnOptionalPresentForUserGivenPrimaryMFAMethods() {
        MFAMethod mfaMethod = new MFAMethod();
        mfaMethod.setEnabled(true);
        userCredentials.setMfaMethods(List.of(mfaMethod));
        var response = MfaHelper.getPrimaryMFAMethod(userCredentials);
        assertTrue(response.isPresent());
    }

    @Test
    void shouldReturnOptionalEmptyWhenMFAMethodIsNotEnabled() {
        MFAMethod mfaMethod = new MFAMethod();
        mfaMethod.setEnabled(false);
        userCredentials.setMfaMethods(List.of(mfaMethod));
        var response = MfaHelper.getPrimaryMFAMethod(userCredentials);
        assertTrue(response.isEmpty());
    }

    @Test
    void shouldReturnOptionalEmptyForUserGivenNoPrimaryMFAMethods() {
        var response = MfaHelper.getPrimaryMFAMethod(userCredentials);
        assertTrue(response.isEmpty());
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
