package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DecisionErrorTest {

    @Test
    void shouldHaveCorrectEnumValues() {
        // Then
        assertEquals("STORAGE_SERVICE_ERROR", DecisionError.STORAGE_SERVICE_ERROR.name());
    }
}
