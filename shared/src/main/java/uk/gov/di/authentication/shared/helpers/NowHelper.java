package uk.gov.di.authentication.shared.helpers;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class NowHelper {

    public static Date now() {
        return Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant());
    }
}
