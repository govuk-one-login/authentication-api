package uk.gov.di.authentication.shared.services;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import uk.gov.di.authentication.entity.Application;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.service.notify.NotificationClientException;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class CloudwatchMetricsServiceTest {

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CloudwatchMetricsService.class);

    @Nested
    class GetDimensions {
        @Test
        void shouldAlwaysIncludeEnvironmentDimensionFromConfiguration() {
            var randomEnvironment = RandomStringUtils.secure().nextAlphanumeric(10);

            var service =
                    new CloudwatchMetricsService(configurationWithEnvironment(randomEnvironment));

            var dimensions = service.getDimensions(Collections.emptyMap());

            assertThat(dimensions.getDimensionKeys().size(), is(1));
            assertThat(dimensions.getDimensionValue("Environment"), is(randomEnvironment));
        }
    }

    @Nested
    class EmitMetric {
        @Test
        void shouldEmitMetricWithNamespace() {
            var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));
            var metricsLogger = Mockito.mock(MetricsLogger.class);

            service.emitMetric("Metric", 1, Collections.emptyMap(), metricsLogger);

            verify(metricsLogger).setNamespace("Authentication");
        }

        @Test
        void shouldEmitMetricWithDimensions() {
            var dimensionSet = ArgumentCaptor.forClass(DimensionSet.class);
            var metricsLogger = Mockito.mock(MetricsLogger.class);

            var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

            service.emitMetric("Metric", 1, Map.of("Key1", "Value1"), metricsLogger);

            verify(metricsLogger).putDimensions(dimensionSet.capture());

            assertThat(dimensionSet.getValue().getDimensionValue("Key1"), is("Value1"));
            assertThat(dimensionSet.getValue().getDimensionKeys().size(), is(1));
        }

        @Test
        void shouldEmitMetricCatchValidationExceptions() {
            var metricsLogger = new MetricsLogger();
            var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

            service.emitMetric(
                    new String(new char[2000]).replace('\0', 'A'),
                    1,
                    Map.of("Key1", "Value1"),
                    metricsLogger);
            service.emitMetric("Metric", 1, Map.of("Key1", ""), metricsLogger);
            service.emitMetric("Metric", 1, Map.of("", "Value1"), metricsLogger);

            List<LogEvent> events = logging.events();
            assertThat(
                    events,
                    hasItem(
                            withMessageContaining(
                                    "Error emitting metric: Metric name exceeds maximum length of 1024")));
            assertThat(
                    events,
                    hasItem(
                            withMessageContaining(
                                    "Error emitting metric: Dimension value cannot be empty")));
            assertThat(
                    events,
                    hasItem(
                            withMessageContaining(
                                    "Error emitting metric: Dimension name cannot be empty")));
            assertEquals(3, events.size());
        }
    }

    @Nested
    class IncrementMfaMethodCounter {
        @Test
        void shouldIncrementMfaMethodCounterWithCorrectDimensions() {
            var spyService = Mockito.spy(CloudwatchMetricsService.class);

            spyService.incrementMfaMethodCounter(
                    "test",
                    "SomeOperation",
                    "SomeResult",
                    ACCOUNT_MANAGEMENT,
                    "AUTH_APP",
                    PriorityIdentifier.BACKUP);

            var expectedDimensions =
                    Map.of(
                            "Environment",
                            "test",
                            "Operation",
                            "SomeOperation",
                            "Result",
                            "SomeResult",
                            "JourneyType",
                            "ACCOUNT_MANAGEMENT",
                            "MfaMethodType",
                            "AUTH_APP",
                            "PriorityIdentifier",
                            "BACKUP");

            verify(spyService).putEmbeddedValue("MfaMethodOperationCount", 1, expectedDimensions);
        }
    }

    @Nested
    class EmitMetricForNotification {
        @Test
        void shouldEmitSmsNotificationSentMetricWithCorrectDimensions() {
            var spyService =
                    Mockito.spy(new CloudwatchMetricsService(configurationWithEnvironment("test")));

            spyService.emitMetricForNotification(
                    NotificationType.VERIFY_PHONE_NUMBER,
                    "+447700900123",
                    false,
                    Application.AUTHENTICATION);

            var expectedDimensions =
                    Map.of(
                            "Environment", "test",
                            "Application", "Authentication",
                            "NotificationType", "VERIFY_PHONE_NUMBER",
                            "IsTest", "false",
                            "Country", "44");

            verify(spyService).incrementCounter("SmsNotificationSent", expectedDimensions);
        }

        @Test
        void shouldEmitEmailNotificationSentMetricWithCorrectDimensions() {
            var spyService =
                    Mockito.spy(new CloudwatchMetricsService(configurationWithEnvironment("test")));

            spyService.emitMetricForNotification(
                    NotificationType.VERIFY_EMAIL,
                    "test@example.com",
                    true,
                    Application.ONE_LOGIN_HOME);

            var expectedDimensions =
                    Map.of(
                            "Environment", "test",
                            "Application", "OneLoginHome",
                            "NotificationType", "VERIFY_EMAIL",
                            "IsTest", "true");

            verify(spyService).incrementCounter("EmailNotificationSent", expectedDimensions);
        }

        @Test
        void shouldEmitSmsNotificationErrorMetricWithHttpError() {
            var spyService =
                    Mockito.spy(new CloudwatchMetricsService(configurationWithEnvironment("test")));
            var notificationException = new NotificationClientException("Error");

            spyService.emitMetricForNotificationError(
                    NotificationType.MFA_SMS,
                    "+447700900123",
                    false,
                    Application.AUTHENTICATION,
                    notificationException);

            var expectedDimensions =
                    Map.of(
                            "Environment", "test",
                            "Application", "Authentication",
                            "NotificationType", "MFA_SMS",
                            "IsTest", "false",
                            "Country", "44",
                            "NotificationHttpError", "400");

            verify(spyService).incrementCounter("SmsNotificationError", expectedDimensions);
        }

        @Test
        void shouldEmitEmailNotificationErrorMetricWithHttpError() {
            var spyService =
                    Mockito.spy(new CloudwatchMetricsService(configurationWithEnvironment("test")));
            var notificationException = new NotificationClientException("Error");

            spyService.emitMetricForNotificationError(
                    NotificationType.RESET_PASSWORD_WITH_CODE,
                    "test@example.com",
                    false,
                    Application.AUTHENTICATION,
                    notificationException);

            var expectedDimensions =
                    Map.of(
                            "Environment", "test",
                            "Application", "Authentication",
                            "NotificationType", "RESET_PASSWORD_WITH_CODE",
                            "IsTest", "false",
                            "NotificationHttpError", "400");

            verify(spyService).incrementCounter("EmailNotificationError", expectedDimensions);
        }

        @Test
        void shouldHandleInvalidPhoneNumberCountry() {
            var spyService =
                    Mockito.spy(new CloudwatchMetricsService(configurationWithEnvironment("test")));

            spyService.emitMetricForNotification(
                    NotificationType.VERIFY_PHONE_NUMBER,
                    "invalid-phone",
                    false,
                    Application.AUTHENTICATION);

            var expectedDimensions =
                    Map.of(
                            "Environment", "test",
                            "Application", "Authentication",
                            "NotificationType", "VERIFY_PHONE_NUMBER",
                            "IsTest", "false",
                            "Country", "INVALID");

            verify(spyService).incrementCounter("SmsNotificationSent", expectedDimensions);
        }
    }

    private static ConfigurationService configurationWithEnvironment(String test) {
        return new ConfigurationService() {
            @Override
            public String getEnvironment() {
                return test;
            }
        };
    }
}
