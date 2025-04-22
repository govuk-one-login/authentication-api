package uk.gov.di.authentication.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaDetailDeserializer;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class MfaDetailDeserializerTest {

    @Test
    void shouldDeserializeSmsMfaDetail() {
        String json =
                "{\"mfaMethodType\": \"SMS\", \"phoneNumber\": \"+447700900123\", \"otp\":\"123456\"}";
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();
        MfaDetail mfaDetail = gson.fromJson(json, MfaDetail.class);
        assertInstanceOf(RequestSmsMfaDetail.class, mfaDetail);
        assertEquals(MFAMethodType.SMS, ((RequestSmsMfaDetail) mfaDetail).mfaMethodType());
        assertEquals("+447700900123", ((RequestSmsMfaDetail) mfaDetail).phoneNumber());
    }

    @Test
    void shouldDeserializeAuthAppMfaDetail() {
        String json = "{\"mfaMethodType\": \"AUTH_APP\", \"credential\": \"123456\"}";
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();
        MfaDetail mfaDetail = gson.fromJson(json, MfaDetail.class);
        assertInstanceOf(RequestAuthAppMfaDetail.class, mfaDetail);
        assertEquals(MFAMethodType.AUTH_APP, ((RequestAuthAppMfaDetail) mfaDetail).mfaMethodType());
        assertEquals("123456", ((RequestAuthAppMfaDetail) mfaDetail).credential());
    }
}
