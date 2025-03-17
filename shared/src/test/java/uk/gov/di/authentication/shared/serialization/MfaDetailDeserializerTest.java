package uk.gov.di.authentication.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.mfa.AuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.SmsMfaDetail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class MfaDetailDeserializerTest {

    @Test
    void shouldDeserializeSmsMfaDetail() {
        String json = "{\"mfaMethodType\": \"SMS\", \"phoneNumber\": \"+447700900123\"}";
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();
        MfaDetail mfaDetail = gson.fromJson(json, MfaDetail.class);
        assertInstanceOf(SmsMfaDetail.class, mfaDetail);
        assertEquals(MFAMethodType.SMS, ((SmsMfaDetail) mfaDetail).mfaMethodType());
        assertEquals("+447700900123", ((SmsMfaDetail) mfaDetail).phoneNumber());
    }

    @Test
    void shouldDeserializeAuthAppMfaDetail() {
        String json = "{\"mfaMethodType\": \"AUTH_APP\", \"credential\": \"123456\"}";
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();
        MfaDetail mfaDetail = gson.fromJson(json, MfaDetail.class);
        assertInstanceOf(AuthAppMfaDetail.class, mfaDetail);
        assertEquals(MFAMethodType.AUTH_APP, ((AuthAppMfaDetail) mfaDetail).mfaMethodType());
        assertEquals("123456", ((AuthAppMfaDetail) mfaDetail).credential());
    }
}
