package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TrackingErrorTest {

    @Test
    void shouldHaveCorrectEnumValues() {
        assertEquals("STORAGE_SERVICE_ERROR", TrackingError.STORAGE_SERVICE_ERROR.name());
    }
}
