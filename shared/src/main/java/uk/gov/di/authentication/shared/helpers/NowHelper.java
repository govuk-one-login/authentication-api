package uk.gov.di.authentication.shared.helpers;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class NowHelper {

    public static Date now() {
        return Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant());
    }

    public static Date nowPlus(long amount, ChronoUnit unit) {
        return Date.from(
                LocalDateTime.now().plus(amount, unit).atZone(ZoneId.of("UTC")).toInstant());
    }
}
