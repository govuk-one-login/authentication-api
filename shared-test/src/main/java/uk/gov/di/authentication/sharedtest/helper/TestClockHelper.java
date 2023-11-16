package uk.gov.di.authentication.sharedtest.helper;

import uk.gov.di.authentication.shared.helpers.NowHelper.NowClock;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

public class TestClockHelper {
    public static NowClock getInstance() {
        return new NowClock(
                Clock.fixed(Instant.parse("2007-12-03T10:15:30.00Z"), ZoneId.of("UTC")));
    }
}
