package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthenticationMethodTest {

    @Test
    void testEmailType() {
        AuthenticationMethod type = AuthenticationMethod.EMAIL;
        assertEquals("EMAIL", type.getValue(), "EMAIL type should return 'EMAIL'");
    }

    @Test
    void testPasswordType() {
        AuthenticationMethod type = AuthenticationMethod.PASSWORD;
        assertEquals("PASSWORD", type.getValue(), "PASSWORD type should return 'PASSWORD'");
    }

    @Test
    void testAuthAppType() {
        AuthenticationMethod type = AuthenticationMethod.AUTH_APP;
        assertEquals("AUTH_APP", type.getValue(), "AUTH_APP type should return 'AUTH_APP'");
    }

    @Test
    void testSmsType() {
        AuthenticationMethod type = AuthenticationMethod.SMS;
        assertEquals("SMS", type.getValue(), "SMS type should return 'SMS'");
    }
}
