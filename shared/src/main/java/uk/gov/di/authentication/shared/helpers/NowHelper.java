package uk.gov.di.authentication.shared.helpers;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class NowHelper {

    public static Date now() {
        return Date.from(Clock.systemUTC().instant());
    }

    public static Date nowPlus(long amount, ChronoUnit unit) {
        return Date.from(Clock.systemUTC().instant().plus(amount, unit));
    }

    public static Date nowMinus(long amount, ChronoUnit unit) {
        return Date.from(Clock.systemUTC().instant().minus(amount, unit));
    }
}
