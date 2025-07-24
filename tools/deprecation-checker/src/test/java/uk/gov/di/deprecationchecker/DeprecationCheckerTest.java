package uk.gov.di.deprecationchecker;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DeprecationCheckerTest {
    @Test
    void initialTest() {
        assertDoesNotThrow(DeprecationChecker::main);
    }
}
