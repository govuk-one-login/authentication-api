package uk.gov.di.authentication.shared.helpers;

import java.text.SimpleDateFormat;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class NowHelper {

    private static final NowClock clock = new NowClock(Clock.systemUTC());

    private static final SimpleDateFormat timestampFormat =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS");

    public static Date now() {
        return clock.now();
    }

    public static Date nowPlus(long amount, ChronoUnit unit) {
        return clock.nowPlus(amount, unit);
    }

    public static Date nowMinus(long amount, ChronoUnit unit) {
        return clock.nowMinus(amount, unit);
    }

    public static String toTimestampString(Date date) {
        return timestampFormat.format(date);
    }

    public static class NowClock {
        private final Clock clock;

        public NowClock(Clock clock) {
            this.clock = clock;
        }

        public Date now() {
            return Date.from(clock.instant());
        }

        public Date nowPlus(long amount, ChronoUnit unit) {
            return Date.from(clock.instant().plus(amount, unit));
        }

        public Date nowMinus(long amount, ChronoUnit unit) {
            return Date.from(clock.instant().minus(amount, unit));
        }
    }
}
