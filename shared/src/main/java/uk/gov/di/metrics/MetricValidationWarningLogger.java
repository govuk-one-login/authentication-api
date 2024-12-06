/*
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 *   Modifications made:
 *   - GDS (2024-12): Rather than throwing errors, this logs warnings should
 *     validation of a metric, dimension or namespace fail
 */

package uk.gov.di.metrics;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.cloudwatchlogs.emf.model.Unit;

public class MetricValidationWarningLogger {
    private static final Logger LOG = LogManager.getLogger(MetricValidationWarningLogger.class);

    public static final short MAX_DIMENSION_NAME_LENGTH = 250;
    public static final short MAX_DIMENSION_VALUE_LENGTH = 1024;
    public static final short MAX_METRIC_NAME_LENGTH = 1024;
    public static final short MAX_NAMESPACE_LENGTH = 256;
    public static final String VALID_NAMESPACE_REGEX = "^[a-zA-Z0-9._#:/-]+$";

    private MetricValidationWarningLogger() {
        throw new IllegalStateException("Utility class");
    }

    public static void validateDimensionSet(String dimensionName, String dimensionValue) {

        if (dimensionName == null || dimensionName.trim().isEmpty()) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension name cannot be empty {}",
                    getStackTrace());
            return;
        }

        if (dimensionValue == null || dimensionValue.trim().isEmpty()) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension value cannot be empty {}",
                    getStackTrace());
            return;
        }

        if (dimensionName.length() > MAX_DIMENSION_NAME_LENGTH) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension name exceeds maximum length of {}: {} {}",
                    MAX_DIMENSION_NAME_LENGTH,
                    dimensionName,
                    getStackTrace());
        }

        if (dimensionValue.length() > MAX_DIMENSION_VALUE_LENGTH) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension value exceeds maximum length of {}}: {} {}",
                    MAX_DIMENSION_VALUE_LENGTH,
                    dimensionValue,
                    getStackTrace());
        }

        if (!StringUtils.isAsciiPrintable(dimensionName)) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension name has invalid characters: {} {}",
                    dimensionName,
                    getStackTrace());
        }

        if (!StringUtils.isAsciiPrintable(dimensionValue)) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension value has invalid characters: {} {}",
                    dimensionValue,
                    getStackTrace());
        }

        if (dimensionName.startsWith(":")) {
            LOG.warn(
                    "Would throw InvalidDimensionException. Dimension name cannot start with ':' {}",
                    getStackTrace());
        }
    }

    public static void validateMetric(String name, double value, Unit unit) {
        if (name == null || name.trim().isEmpty()) {
            LOG.warn(
                    "Would throw InvalidMetricException. Metric name {} must include at least one non-whitespace character {}",
                    name,
                    getStackTrace());
            return;
        }

        if (name.length() > MAX_METRIC_NAME_LENGTH) {
            LOG.warn(
                    "Would throw InvalidMetricException. Metric name exceeds maximum length of {}: {} {}",
                    MAX_METRIC_NAME_LENGTH,
                    name,
                    getStackTrace());
        }

        if (!Double.isFinite(value)) {
            LOG.warn(
                    "Would throw InvalidMetricException. Metric value is not a number {}",
                    getStackTrace());
        }

        if (unit == null) {
            LOG.warn(
                    "Would throw InvalidMetricException. Metric unit cannot be null {}",
                    getStackTrace());
        }
    }

    public static void validateNamespace(String namespace) {
        if (namespace == null || namespace.trim().isEmpty()) {
            LOG.warn(
                    "Would throw InvalidNamespaceException. Namespace must include at least one non-whitespace character {}",
                    getStackTrace());
            return;
        }

        if (namespace.length() > MAX_NAMESPACE_LENGTH) {
            LOG.warn(
                    "Would throw InvalidNamespaceException. Namespace exceeds maximum length of {}: {} {}",
                    MAX_NAMESPACE_LENGTH,
                    namespace,
                    getStackTrace());
        }

        if (!namespace.matches(VALID_NAMESPACE_REGEX)) {
            LOG.warn(
                    "Would throw InvalidNamespaceException. Namespace contains invalid characters: {} {}",
                    namespace,
                    getStackTrace());
        }
    }

    public static String getStackTrace() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

        StringBuilder stackTraceString = new StringBuilder();
        for (StackTraceElement element : stackTrace) {
            stackTraceString.append("\n").append(element);
        }

        return stackTraceString.toString();
    }
}
