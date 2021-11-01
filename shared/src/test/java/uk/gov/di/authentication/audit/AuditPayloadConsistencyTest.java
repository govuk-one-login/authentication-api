package uk.gov.di.authentication.audit;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.AuditEvent.User;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.MatcherAssert.assertThat;

class AuditPayloadConsistencyTest {

    @Test
    void shouldHandleEmptyObjects() {
        var emptyObject = AuditEvent.newBuilder().build();

        assertThat(
                eventWithSignature("signature", emptyObject),
                hasHashValue("6f4c1976b0660de7ada9cf0eb39d261e8cb293a9e0d208eeccbe29bf9247fe90"));
    }

    @Test
    void shouldHandleFullObjects() {

        var emptyObject =
                AuditEvent.newBuilder()
                        .setEventId("test-setEventId")
                        .setRequestId("test-setRequestId")
                        .setSessionId("test-setSessionId")
                        .setClientId("test-setClientId")
                        .setTimestamp("test-setTimestamp")
                        .setEventName("test-setEventName")
                        .setUser(
                                User.newBuilder()
                                        .setId("test-setId")
                                        .setEmail("test-setEmail")
                                        .setIpAddress("test-setIpAddress")
                                        .setPhoneNumber("test-setPhoneNumber")
                                        .build())
                        .putExtensions("test-putExtensions", "test-putExtensions")
                        .putPlatform("test-putPlatform", "test-putPlatform")
                        .build();

        assertThat(
                eventWithSignature("signature", emptyObject),
                hasHashValue("c988acfe4e7f90d39d5749f8842573d8d091cdd9e5e5a5d79ca65b59508e82a5"));
    }

    public SignedAuditEvent eventWithSignature(String signature, AuditEvent event) {
        return SignedAuditEvent.newBuilder()
                .setSignature(ByteString.copyFrom(signature.getBytes()))
                .setPayload(event.toByteString())
                .build();
    }

    private static Matcher<SignedAuditEvent> hasHashValue(String hash) {

        return new TypeSafeDiagnosingMatcher<>() {
            @Override
            protected boolean matchesSafely(
                    SignedAuditEvent item, Description mismatchDescription) {
                try {
                    var hashedPayload =
                            Hex.encodeHexString(
                                    MessageDigest.getInstance("SHA-256")
                                            .digest(item.toByteArray()));
                    var equals = hashedPayload.equals(hash);

                    if (!equals) {
                        mismatchDescription
                                .appendText("a SignedAuditEvent with SHA256 hash [")
                                .appendText(hashedPayload)
                                .appendText("]");
                    }
                    return equals;
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText("a SignedAuditEvent with SHA256 hash [")
                        .appendText(hash)
                        .appendText("]");
            }
        };
    }
}
