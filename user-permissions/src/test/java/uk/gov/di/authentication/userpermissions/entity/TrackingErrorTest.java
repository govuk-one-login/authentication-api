package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TrackingErrorTest {

    @Test
    void shouldHaveCorrectEnumValues() {
        // Then
        assertEquals("UNKNOWN", TrackingError.UNKNOWN.name());
    }
}
