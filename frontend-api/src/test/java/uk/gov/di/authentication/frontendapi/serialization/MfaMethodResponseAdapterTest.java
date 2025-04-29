package uk.gov.di.authentication.frontendapi.serialization;

import com.google.gson.stream.JsonReader;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.mfa.AuthAppMfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.SmsMfaMethodResponse;

import java.io.IOException;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaMethodResponseAdapterTest {
    @Test
    void shouldThrowWithInvalidType() {
        String json =
                "{\"id\":\"sms-id\",\"type\":\"WHOKNOWS\",\"priority\":\"DEFAULT\",\"redactedPhoneNumber\":\"123\"}";
        JsonReader reader = new JsonReader(new StringReader(json));
        MfaMethodResponseAdapter adapter = new MfaMethodResponseAdapter();
        assertThrows(IllegalArgumentException.class, () -> adapter.read(reader));
    }

    @Test
    void shouldReadSmsMfaMethodResponse() throws IOException {
        String json =
                "{\"id\":\"sms-id\",\"type\":\"SMS\",\"priority\":\"DEFAULT\",\"redactedPhoneNumber\":\"123\"}";
        JsonReader reader = new JsonReader(new StringReader(json));
        MfaMethodResponseAdapter adapter = new MfaMethodResponseAdapter();
        MfaMethodResponse mfaMethodResponse = adapter.read(reader);
        assertEquals(SmsMfaMethodResponse.class, mfaMethodResponse.getClass());
    }

    @Test
    void shouldReadAuthAppMfaMethodResponse() throws IOException {
        String json =
                "{\"id\":\"sms-id\",\"type\":\"AUTH_APP\",\"priority\":\"DEFAULT\",\"redactedPhoneNumber\":\"123\"}";
        JsonReader reader = new JsonReader(new StringReader(json));
        MfaMethodResponseAdapter adapter = new MfaMethodResponseAdapter();
        MfaMethodResponse mfaMethodResponse = adapter.read(reader);
        assertEquals(AuthAppMfaMethodResponse.class, mfaMethodResponse.getClass());
    }
}
