package uk.gov.di.authentication.userpermissions.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DecisionErrorTest {

    @Test
    void shouldHaveCorrectEnumValues() {
        // Then
        assertEquals("UNKNOWN", DecisionError.UNKNOWN.name());
    }
}
