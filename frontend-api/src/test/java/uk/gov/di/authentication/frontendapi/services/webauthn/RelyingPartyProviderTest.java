package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.RelyingParty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RelyingPartyProviderTest {

    @Mock private ConfigurationService configurationService;

    private static final String RELYING_PARTY_ID_A = "test.example.com";
    private static final String RELYING_PARTY_NAME_A = "Test Service";
    private static final String RELYING_PARTY_ID_B = "other.example.com";
    private static final String RELYING_PARTY_NAME_B = "Other Service";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(configurationService.getWebAuthnRelyingPartyId()).thenReturn(RELYING_PARTY_ID_A);
        when(configurationService.getWebAuthnRelyingPartyName()).thenReturn(RELYING_PARTY_NAME_A);
    }

    @Nested
    class Provide {
        @Test
        void returnsRelyingPartyInstance() {
            RelyingParty result = RelyingPartyProvider.provide(configurationService);

            assertThat(result, is(notNullValue()));
            assertThat(result.getIdentity().getId(), equalTo(RELYING_PARTY_ID_A));
            assertThat(result.getIdentity().getName(), equalTo(RELYING_PARTY_NAME_A));
        }

        @Test
        void returnsSameInstanceOnMultipleCalls() {
            RelyingParty first = RelyingPartyProvider.provide(configurationService);
            RelyingParty second = RelyingPartyProvider.provide(configurationService);

            assertThat(first, sameInstance(second));
        }

        @Test
        void returnsDifferentInstancesForDifferentConfigurationServices() {
            ConfigurationService otherConfigService = mock(ConfigurationService.class);
            when(otherConfigService.getWebAuthnRelyingPartyId()).thenReturn(RELYING_PARTY_ID_B);
            when(otherConfigService.getWebAuthnRelyingPartyName()).thenReturn(RELYING_PARTY_NAME_B);

            RelyingParty first = RelyingPartyProvider.provide(configurationService);
            RelyingParty second = RelyingPartyProvider.provide(otherConfigService);

            assertThat(first, not(sameInstance(second)));
            assertThat(first.getIdentity().getId(), equalTo(RELYING_PARTY_ID_A));
            assertThat(second.getIdentity().getId(), equalTo(RELYING_PARTY_ID_B));
        }
    }
}
