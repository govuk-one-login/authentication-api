package uk.gov.di.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VcapServicesTest {

    @Test
    void shouldReadVcap() {

        var input =
                """
        {
            "postgres": [
                {
                    "credentials": {
                        "name": "database-name",
                        "host": "database-host",
                        "port": 1234,
                        "username": "database-username",
                        "password": "database-password"
                    }
                }
            ]
        }
        """;

        var credentials = VcapServices.readPostgresConfiguration(input).orElseThrow();

        assertEquals(credentials.name(), "database-name");
        assertEquals(credentials.host(), "database-host");
        assertEquals(credentials.port(), "1234");
        assertEquals(credentials.username(), "database-username");
        assertEquals(credentials.password(), "database-password");
    }

    @Test
    void handlesNonJson() {
        assertTrue(VcapServices.readPostgresConfiguration("not-json").isEmpty());
    }

    @Test
    void handlesMissingPostgresKey() {
        assertTrue(VcapServices.readPostgresConfiguration("{}").isEmpty());
    }

    @Test
    void handlesEmptyPostgresKey() {
        assertTrue(VcapServices.readPostgresConfiguration("{'postgres': []}").isEmpty());
    }

    @Test
    void ignoresIrrelevantFields() {
        var input =
                """
        {
            "some-other-field": [],
            "postgres": [{
                "some-other-field": "other-value",
                "credentials": {
                    "name": "database-name",
                    "host": "database-host",
                    "port": 1234,
                    "username": "database-username",
                    "password": "database-password",
                    "some-other-field": "other-value"
                }
            }]
        }
        """;

        assertTrue(VcapServices.readPostgresConfiguration(input).isPresent());
    }

    @Test
    void requiresAllFieldsToBePresent() {
        var input =
                """
        {
            "postgres": [{
                "credentials": {
                    "name": "database-name"
                }
            }]
        }
        """;

        assertTrue(VcapServices.readPostgresConfiguration(input).isEmpty());
    }
}
