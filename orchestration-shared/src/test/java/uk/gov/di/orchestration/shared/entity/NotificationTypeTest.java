package uk.gov.di.orchestration.shared.entity;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.AuthId;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.IdentId;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotComponent;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrRequest;
import uk.gov.di.orchestration.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.NotificationType.VERIFY_EMAIL;

class NotificationTypeTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWithLanguageEN() {
        assertThat(
                VERIFY_EMAIL.getTemplateName(SupportedLanguage.EN),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnWelshTemplateForVerifyEmailWithLanguageCY() {
        assertThat(
                VERIFY_EMAIL.getTemplateName(SupportedLanguage.CY),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID_CY"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyPhoneNumberWithLanguageEN() {
        MatcherAssert.assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName(SupportedLanguage.EN),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnWelshTemplateForVerifyPhoneNumberWithLanguageCY() {
        assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName(SupportedLanguage.CY),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageEN() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.EN, configurationService),
                equalTo("12345"));
    }

    @Test
    void shouldReturnCYTemplateForVerifyEmailWhenLanguageCYAndSingleTemplatePerLanguage() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        when(configurationService.isNotifyTemplatePerLanguage()).thenReturn(true);
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("67890"));
    }

    @Test
    void shouldReturnENTemplateForVerifyEmailWhenLanguageCYAndNotSingleTemplatePerLanguage() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        when(configurationService.isNotifyTemplatePerLanguage()).thenReturn(false);
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("12345"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageCYButTemplateMissing() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("12345"));
    }

    public static class VotComponentTest {

        @Test
        void emptyShouldReturnEmptyComponent() {
            var component = VotComponent.empty(IdentId.class);
            assertThat(component, is(empty()));
        }

        @Test
        void ofShouldReturnComponentOfProvidedElementsInNaturalOrder() {
            var component = VotComponent.of(AuthId.CL, AuthId.CM);
            assertThat(component, contains(AuthId.CL, AuthId.CM));

            var componentReversed = VotComponent.of(AuthId.CM, AuthId.CL);
            assertThat(componentReversed, contains(AuthId.CL, AuthId.CM));
        }

        @ParameterizedTest
        @MethodSource("toStringTestCases")
        void toStringShouldReturnCorrectlyFormattedString(VotComponent component, String expected) {
            assertThat(component.toString(), is(equalTo(expected)));
        }

        public static Stream<Arguments> toStringTestCases() {
            return Stream.of(
                    arguments(VotComponent.empty(AuthId.class), ""),
                    arguments(VotComponent.of(AuthId.CL), "Cl"),
                    arguments(VotComponent.of(IdentId.P0), "P0"),
                    arguments(VotComponent.of(AuthId.CL, AuthId.CM), "Cl.Cm"),
                    arguments(VotComponent.of(AuthId.CM, AuthId.CL), "Cl.Cm"));
        }

        @ParameterizedTest
        @MethodSource("equalsAndHashCodeTestCases")
        void equalsAndHashCodeShouldBehaveCorrectly(
                VotComponent component1, VotComponent component2, boolean areEqual) {
            assertThat(component1.equals(component2), is(equalTo(areEqual)));
            assertThat(component2.equals(component1), is(equalTo(areEqual)));

            if (areEqual) {
                assertThat(component1.hashCode(), is(equalTo(component2.hashCode())));
            }
        }

        public static Stream<Arguments> equalsAndHashCodeTestCases() {
            var componentEmptyCredA = VotComponent.empty(AuthId.class);
            var componentEmptyCredB = VotComponent.empty(AuthId.class);
            var componentP2A = VotComponent.of(IdentId.P2);
            var componentP2B = VotComponent.of(IdentId.P2);
            var componentClCmA = VotComponent.of(AuthId.CL, AuthId.CM);
            var componentClCmB = VotComponent.of(AuthId.CL, AuthId.CM);
            var componentCmClA = VotComponent.of(AuthId.CM, AuthId.CL);
            var componentCmClB = VotComponent.of(AuthId.CM, AuthId.CL);
            var componentCL = VotComponent.of(AuthId.CL);
            var componentC1 = VotComponent.of(AuthId.C1);
            var componentC2 = VotComponent.of(AuthId.C2);
            var componentCl = VotComponent.of(AuthId.CL);
            var componentClCl = VotComponent.of(AuthId.CL, AuthId.CL);

            return Stream.of(
                    arguments(componentEmptyCredA, componentEmptyCredB, true),
                    arguments(componentP2A, componentP2B, true),
                    arguments(componentClCmA, componentClCmB, true),
                    arguments(componentCmClA, componentCmClB, true),
                    arguments(componentCl, componentClCl, true),
                    arguments(componentEmptyCredA, componentClCmA, false),
                    arguments(componentClCmA, componentEmptyCredA, false),
                    arguments(componentCL, componentC1, false),
                    arguments(componentClCmA, componentC2, false));
        }

        @Test
        void compareToShouldUseBackToFrontLexicographicalOrdering() {
            var listOfComponents =
                    List.of(
                            VotComponent.of(AuthId.C2),
                            VotComponent.of(AuthId.CL),
                            VotComponent.of(AuthId.CM),
                            VotComponent.of(AuthId.CL, AuthId.CM),
                            VotComponent.of(AuthId.CM),
                            VotComponent.of(AuthId.CL),
                            VotComponent.empty(AuthId.class),
                            VotComponent.of(AuthId.C4),
                            VotComponent.of(AuthId.C3),
                            VotComponent.of(AuthId.C1));

            assertThat(
                    listOfComponents.stream().sorted().toList(),
                    contains(
                            VotComponent.empty(AuthId.class),
                            VotComponent.of(AuthId.CL),
                            VotComponent.of(AuthId.CL),
                            VotComponent.of(AuthId.CM),
                            VotComponent.of(AuthId.CM),
                            VotComponent.of(AuthId.CL, AuthId.CM),
                            VotComponent.of(AuthId.C1),
                            VotComponent.of(AuthId.C2),
                            VotComponent.of(AuthId.C3),
                            VotComponent.of(AuthId.C4)));
        }

        @Test
        void shouldThrowWhenTryingToEditContents() {
            var component1 = VotComponent.empty(AuthId.class);
            assertThrows(UnsupportedOperationException.class, () -> component1.add(AuthId.C1));

            var component2 = VotComponent.of(AuthId.CL, AuthId.CM);
            assertThrows(UnsupportedOperationException.class, () -> component2.remove(AuthId.CL));
        }
    }

    public static class VtrListTest {

        @Test
        void emptyShouldReturnEmptyList() {
            var vtr = VtrRequest.empty();
            assertThat(vtr, is(empty()));
        }

        @Test
        void ofShouldReturnSameElementsAsInput() {
            var componentEmptyCred = VotComponent.empty(AuthId.class);
            var componentEmptyIdent = VotComponent.empty(IdentId.class);
            var componentC1 = VotComponent.of(AuthId.C1);
            var componentP0 = VotComponent.of(IdentId.P0);
            var vector1 = new uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust(componentEmptyCred, componentEmptyIdent);
            var vector2 = new uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust(componentC1, componentEmptyIdent);
            var vector3 = new VectorOfTrust(componentC1, componentP0);
            var vtr = VtrRequest.of(vector1, vector2, vector3);
            assertThat(vtr, containsInAnyOrder(vector1, vector2, vector3));
        }
    }
}
