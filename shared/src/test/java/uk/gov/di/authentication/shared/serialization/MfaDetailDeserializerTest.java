package uk.gov.di.authentication.shared.serialization;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaDetailDeserializer;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        assertEquals(MFAMethodType.SMS, mfaDetail.mfaMethodType());
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
        assertEquals(MFAMethodType.AUTH_APP, mfaDetail.mfaMethodType());
        assertEquals("123456", ((RequestAuthAppMfaDetail) mfaDetail).credential());
    }

    @Test
    void shouldHandleUnknownMfaDetail() {
        String json =
                "{\"mfaMethodType\": \"UNKNOWN\", \"phoneNumber\": \"+447700900123\", \"otp\":\"123456\"}";
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();
        assertThrows(JsonParseException.class, () -> gson.fromJson(json, MfaDetail.class));
    }

    @Test
    void needNotHandleNullJsonAsGsonDoesItForUs() {
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();

        var response = gson.fromJson((String) null, MfaDetail.class);

        assertNull(response);
    }

    @Test
    void needNotHandleInvalidJsonAsGsonDoesItForUs() {
        Gson gson =
                new GsonBuilder()
                        .registerTypeAdapter(MfaDetail.class, new MfaDetailDeserializer())
                        .create();

        assertThrows(
                JsonSyntaxException.class,
                () -> gson.fromJson("This is not the json you were looking for.", MfaDetail.class));
    }

    @Test
    void shouldHandleMissingMfaMethodType() {
        var json = new JsonObject();

        var deserializer = new MfaDetailDeserializer();
        JsonParseException exception =
                assertThrows(
                        JsonParseException.class,
                        () -> deserializer.deserialize(json, MfaDetail.class, null));
        assertEquals("MFA method type is missing", exception.getMessage());
    }

    @Test
    void shouldHandleMissingPhoneNumber() {
        var json = new JsonObject();
        json.addProperty("mfaMethodType", "SMS");

        var deserializer = new MfaDetailDeserializer();
        JsonParseException exception =
                assertThrows(
                        JsonParseException.class,
                        () -> deserializer.deserialize(json, MfaDetail.class, null));
        assertEquals("Phone number is missing", exception.getMessage());
    }

    @Test
    void shouldHandleMissingOtp() {
        var json = new JsonObject();
        json.addProperty("mfaMethodType", "SMS");
        json.addProperty("phoneNumber", "0790");

        var deserializer = new MfaDetailDeserializer();
        JsonParseException exception =
                assertThrows(
                        JsonParseException.class,
                        () -> deserializer.deserialize(json, MfaDetail.class, null));
        assertEquals("OTP is missing", exception.getMessage());
    }

    @Test
    void shouldHandleMissingCredential() {
        var json = new JsonObject();
        json.addProperty("mfaMethodType", "AUTH_APP");

        var deserializer = new MfaDetailDeserializer();
        JsonParseException exception =
                assertThrows(
                        JsonParseException.class,
                        () -> deserializer.deserialize(json, MfaDetail.class, null));
        assertEquals("Credential is missing", exception.getMessage());
    }
}
