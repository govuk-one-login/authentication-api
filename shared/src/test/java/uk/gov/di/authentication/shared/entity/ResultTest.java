package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultTest {
    @Test
    void aFailureShouldActAppropriately() {
        var failureValue = "failure";
        var failure = Result.failure(failureValue);

        assertEquals(failureValue, failure.getFailure());
        assertTrue(failure.isFailure());
        assertFalse(failure.isSuccess());
        assertThrows(IllegalStateException.class, failure::getSuccess);
    }

    @Test
    void aSuccessShouldActAppropriately() {
        var successValue = "success";
        var success = Result.success(successValue);

        assertEquals(successValue, success.getSuccess());
        assertFalse(success.isFailure());
        assertTrue(success.isSuccess());
        assertThrows(IllegalStateException.class, success::getFailure);
    }
}
