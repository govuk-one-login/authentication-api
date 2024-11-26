package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static uk.gov.di.orchestration.shared.helpers.SaltHelper.base64ToBytes;
import static uk.gov.di.orchestration.shared.helpers.SaltHelper.byteBufferToBase64;
import static uk.gov.di.orchestration.shared.helpers.SaltHelper.generateNewSalt;

public class SaltHelperTest {
    @Test
    void shouldEncodeAndDecodeBackToSameValue() {
        byte[] saltAsByteArray = generateNewSalt();
        ByteBuffer saltAsByteBuffer = ByteBuffer.wrap(saltAsByteArray);
        String base64EncodedSalt = byteBufferToBase64(saltAsByteBuffer);
        byte[] base64DecodedSalt = base64ToBytes(base64EncodedSalt);

        assertArrayEquals(saltAsByteArray, base64DecodedSalt);
    }
}
