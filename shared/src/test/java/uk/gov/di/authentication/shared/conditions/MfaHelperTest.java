package uk.gov.di.authentication.shared.conditions;

import org.junit.jupiter.api.Test;

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
}
