package uk.gov.di.orchestration.sharedtest.helper;

import org.apache.commons.codec.binary.Base32;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.TimeUnit;

public class AuthAppStub {
    private static final Logger LOG = LogManager.getLogger(AuthAppStub.class);
    private static final int CODE_DIGITS = 6;
    private static final long TIME_WINDOW_IN_MILLISECONDS = TimeUnit.SECONDS.toMillis(30);

    public String getAuthAppOneTimeCode(String secret) {
        return getAuthAppOneTimeCode(secret, NowHelper.now().getTime());
    }

    public String getAuthAppOneTimeCode(String secret, long time) {
        int codeAsInt = getCodeAsInt(decodeBase32Secret(secret), getTimeWindowFromTime(time));
        return Integer.toString(codeAsInt);
    }

    int getCodeAsInt(byte[] secret, long time) {
        byte[] data = new byte[8];

        for (int i = 8; i-- > 0; time >>>= 8) {
            data[i] = (byte) time;
        }

        SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");

        try {
            Mac mac = Mac.getInstance("HmacSHA1");

            mac.init(signKey);

            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0xF;

            long truncatedHash = 0;

            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= (int) Math.pow(10, CODE_DIGITS);

            return (int) truncatedHash;
        } catch (Exception ex) {
            LOG.info("Exception: {}", ex.getMessage());
            return 0;
        }
    }

    public byte[] decodeBase32Secret(String secret) {
        Base32 codec32 = new Base32();
        return codec32.decode(secret);
    }

    private long getTimeWindowFromTime(long time) {
        return time / TIME_WINDOW_IN_MILLISECONDS;
    }
}
