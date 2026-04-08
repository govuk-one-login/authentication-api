#!/usr/bin/env bash
set -euo pipefail

declare DIR
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
readonly DIR
readonly -a ENVIRONMENTS=("authdev1" "authdev2" "authdev3" "dev" "production")

declare -A ALARMS
declare ENVIRONMENT ALARM_NAME METRIC_NAME NAMESPACE THRESHOLD SMS_TYPE EMAIL_ADDRESSES

show_main_menu() {
  echo ""
  echo "🔧 Alarm Management Tool"
  echo "========================"
  echo "Current environment: ${ENVIRONMENT:-none}"
  echo ""
  echo "1. Subscribe to SNS notifications"
  echo "2. Unsubscribe from SNS notifications"
  echo "3. Test alarm functionality"
  echo "4. Show alarm and subscription information"
  echo "5. Change environment"
  echo "6. Exit"
  echo ""
}

select_environment() {
  if [[ -n ${ENVIRONMENT:-} ]]; then
    return
  fi

  echo ""
  echo "Environment Selection (Current: ${ENVIRONMENT:-none})"
  echo "===================================================="
  echo "Available environments:"
  for i in "${!ENVIRONMENTS[@]}"; do
    echo "$((i + 1)). ${ENVIRONMENTS[i]}"
  done
  echo ""
  read -rp "Select environment (1-${#ENVIRONMENTS[@]}): " selection

  if ! [[ ${selection} =~ ^[0-9]+$ ]] || [[ ${selection} -lt 1 ]] || [[ ${selection} -gt ${#ENVIRONMENTS[@]} ]]; then
    echo "Error: Invalid selection"
    exit 1
  fi

  ENVIRONMENT="${ENVIRONMENTS[$((selection - 1))]}"
}

setup_aws() {
  if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
    export AWS_PROFILE="di-authentication-development-AdministratorAccessPermission"
  elif [[ ${ENVIRONMENT} == "production" ]]; then
    export AWS_PROFILE="gds-di-production-admin"
  else
    export AWS_PROFILE="gds-di-development-admin"
  fi
  # shellcheck source=/dev/null
  source "${DIR}/../export_aws_creds.sh"
}

# SNS Subscribe functionality
sns_subscribe() {
  local email topic_arn existing needs_confirmation subscription_output

  read -rp "Enter email address to subscribe: " email

  setup_aws
  init_alarms
  select_alarm

  topic_arn=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].AlarmActions[0]" --output text)

  echo "Alarm: ${ALARM_NAME}"
  echo "Topic ARN: ${topic_arn}"
  echo "Checking for existing subscriptions..."
  existing=$(aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "Subscriptions[?Endpoint=='${email}'].SubscriptionArn" --output text)
  needs_confirmation=false

  if [[ -n ${existing} ]]; then
    echo "Subscription already exists for ${email}:"
    echo "${existing}"

    if [[ ${existing} == "PendingConfirmation" ]]; then
      echo "Subscription is pending confirmation."
      needs_confirmation=true
    else
      echo "Subscription is already confirmed."
    fi
    echo "Skipping subscription creation."
  else
    echo "Creating subscription to ${topic_arn} for ${email}..."

    subscription_output=$(aws sns subscribe \
      --topic-arn "${topic_arn}" \
      --protocol email \
      --notification-endpoint "${email}")

    echo "Subscription created successfully!"
    echo "${subscription_output}"
    needs_confirmation=true
  fi

  echo -e "\nListing subscription details:"
  aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}"

  if [[ ${needs_confirmation} == "true" ]]; then
    echo -e "\nA confirmation email has been sent to ${email}"
    echo "Please check your email and click the confirmation link."
    read -rp "Press Enter after clicking the confirmation link..."

    echo -e "\nUpdated subscription details:"
    aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}"
  else
    echo -e "\nNo confirmation needed - subscription is already active."
  fi
}

# SNS Unsubscribe functionality
sns_unsubscribe() {
  local email topic_arn existing

  read -rp "Enter email address to unsubscribe: " email

  setup_aws
  init_alarms
  select_alarm

  topic_arn=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].AlarmActions[0]" --output text)

  echo "Alarm: ${ALARM_NAME}"
  echo "Topic ARN: ${topic_arn}"
  echo "Checking for existing subscriptions..."
  existing=$(aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "Subscriptions[?Endpoint=='${email}'].SubscriptionArn" --output text)

  if [[ -z ${existing} ]]; then
    echo "No subscription found for ${email}"
    echo "Nothing to unsubscribe."
  else
    echo "Found subscription for ${email}:"
    echo "${existing}"

    if [[ ${existing} == "PendingConfirmation" ]]; then
      echo "Subscription is pending confirmation - cannot unsubscribe pending subscriptions."
      echo "Pending subscriptions will automatically expire if not confirmed."
    else
      echo "Unsubscribing ${email} from ${topic_arn}..."
      aws sns unsubscribe --subscription-arn "${existing}"
      echo "Unsubscribed successfully!"
    fi
  fi

  echo -e "\nRemaining subscription details:"
  aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}"
}

# Test Alarm functionality
init_alarms() {
  # Clear previous alarms to prevent cross-environment contamination
  ALARMS=()

  # SMS Daily Quotas
  local domestic_daily_quota=500000
  local international_daily_quota=6000

  # Early Warning Thresholds (60% of daily quotas)
  local domestic_quota_threshold=$((domestic_daily_quota * 60 / 100))           # 300,000
  local international_quota_threshold=$((international_daily_quota * 60 / 100)) # 3,600

  # Limit Exceeded Thresholds (429 http status code responses from Notify)
  local domestic_limit_threshold=1      # 1+ 429 http status code responses
  local international_limit_threshold=1 # 1+ 429 http status code responses

  # Dynamically discover alarm names to handle P1 prefixes
  local domestic_quota_alarm international_quota_alarm domestic_limit_alarm international_limit_alarm

  domestic_quota_alarm=$(aws cloudwatch describe-alarms --query "MetricAlarms[?starts_with(AlarmName, '${ENVIRONMENT}-') && contains(AlarmName, 'domestic-sms-quota-early-warning-alarm')].AlarmName" --output text)
  international_quota_alarm=$(aws cloudwatch describe-alarms --query "MetricAlarms[?starts_with(AlarmName, '${ENVIRONMENT}-') && contains(AlarmName, 'international-sms-quota-early-warning-alarm')].AlarmName" --output text)
  domestic_limit_alarm=$(aws cloudwatch describe-alarms --query "MetricAlarms[?starts_with(AlarmName, '${ENVIRONMENT}-') && contains(AlarmName, 'domestic-sms-limit-exceeded-alarm')].AlarmName" --output text)
  international_limit_alarm=$(aws cloudwatch describe-alarms --query "MetricAlarms[?starts_with(AlarmName, '${ENVIRONMENT}-') && contains(AlarmName, 'international-sms-limit-exceeded-alarm')].AlarmName" --output text)

  if [[ -n ${domestic_quota_alarm} ]]; then
    ALARMS["${domestic_quota_alarm}"]="DomesticSmsQuotaEarlyWarning:Authentication:${domestic_quota_threshold}:DOMESTIC"
  fi
  if [[ -n ${international_quota_alarm} ]]; then
    ALARMS["${international_quota_alarm}"]="InternationalSmsQuotaEarlyWarning:Authentication:${international_quota_threshold}:INTERNATIONAL"
  fi
  if [[ -n ${domestic_limit_alarm} ]]; then
    ALARMS["${domestic_limit_alarm}"]="SmsLimitExceeded:Authentication:${domestic_limit_threshold}:DOMESTIC"
  fi
  if [[ -n ${international_limit_alarm} ]]; then
    ALARMS["${international_limit_alarm}"]="SmsLimitExceeded:Authentication:${international_limit_threshold}:INTERNATIONAL"
  fi
}

select_alarm() {
  local -a alarm_names sorted_alarms
  local i selection

  if [[ ${#ALARMS[@]} -eq 0 ]]; then
    echo "❌ No alarms found for environment: ${ENVIRONMENT}"
    echo "Please check that alarms exist and you have the correct AWS permissions."
    exit 1
  fi

  for alarm_name in "${!ALARMS[@]}"; do
    alarm_names+=("${alarm_name}")
  done

  mapfile -t sorted_alarms < <(printf '%s\n' "${alarm_names[@]}" | sort)

  echo ""
  echo "Alarm Selection (Environment: ${ENVIRONMENT:-none})"
  echo "================================================="
  echo "Available alarms to test:"
  for i in "${!sorted_alarms[@]}"; do
    echo "$((i + 1)). ${sorted_alarms[i]}"
  done

  echo ""
  read -rp "Select alarm to test (1-${#sorted_alarms[@]}): " selection

  if ! [[ ${selection} =~ ^[0-9]+$ ]] || [[ ${selection} -lt 1 ]] || [[ ${selection} -gt ${#sorted_alarms[@]} ]]; then
    echo "Error: Invalid selection"
    exit 1
  fi

  ALARM_NAME="${sorted_alarms[$((selection - 1))]}"
  echo "Selected alarm: ${ALARM_NAME}"

  IFS=':' read -r METRIC_NAME NAMESPACE THRESHOLD SMS_TYPE <<< "${ALARMS[${ALARM_NAME}]}"
}

test_alarm() {
  local alarm_actions topic_arn subscription_count proceed emails current_state test_value metric_value new_state wait_more

  setup_aws
  init_alarms
  select_alarm

  echo "Testing alarm: ${ALARM_NAME}"

  # Check SNS subscriptions
  echo "Checking SNS topic subscriptions..."
  alarm_actions=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].AlarmActions" --output text)

  EMAIL_ADDRESSES=""
  if [[ -n ${alarm_actions} && ${alarm_actions} != "None" ]]; then
    for topic_arn in ${alarm_actions}; do
      echo "SNS Topic: ${topic_arn}"
      subscription_count=$(aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "length(Subscriptions)" --output text)

      if [[ ${subscription_count} -eq 0 ]]; then
        echo "⚠️  No subscriptions found!"
      else
        echo "📧 Subscriptions (${subscription_count}):"
        aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "Subscriptions[*].[Protocol,Endpoint]" --output table

        emails=$(aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "Subscriptions[?Protocol=='email'].Endpoint" --output text)
        if [[ -n ${emails} ]]; then
          EMAIL_ADDRESSES="${EMAIL_ADDRESSES} ${emails}"
        fi
      fi
      echo ""
    done
  else
    echo "⚠️  WARNING: Alarm has no SNS actions configured!"
    echo ""
  fi

  read -rp "Proceed with alarm test? (y/n): " proceed
  if [[ ${proceed} != "y" && ${proceed} != "Y" ]]; then
    echo "Test cancelled."
    return
  fi

  # Check alarm state
  echo "Checking current alarm state..."
  current_state=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].StateValue" --output text)
  echo "Current alarm state: ${current_state}"

  if [[ ${current_state} == "ALARM" ]]; then
    echo "⚠️  Alarm is already in ALARM state! Cannot test."
    echo ""
    echo "Alarm details:"
    aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].[AlarmName,StateValue,StateReason,StateUpdatedTimestamp]" --output table
    return
  fi

  # Send test metrics
  local sms_count_metric
  if [[ ${METRIC_NAME} == "DomesticSmsQuotaEarlyWarning" ]]; then
    sms_count_metric="DomesticSmsSent"
    test_value=$((THRESHOLD + 100))
  elif [[ ${METRIC_NAME} == "InternationalSmsQuotaEarlyWarning" ]]; then
    sms_count_metric="InternationalSmsSent"
    test_value=$((THRESHOLD + 100))
  elif [[ ${METRIC_NAME} == "SmsLimitExceeded" ]]; then
    # For limit exceeded alarms, send metric directly (simulates 429 http status code responses from Notify)
    test_value=${THRESHOLD}
    echo "Sending ${METRIC_NAME} metric with value ${test_value} (threshold: ${THRESHOLD}) to simulate HTTP status 429 (too many requests) responses from Notify"
    aws cloudwatch put-metric-data \
      --namespace "${NAMESPACE}" \
      --metric-data "MetricName=${METRIC_NAME},Value=${test_value},Unit=Count,Dimensions=[{Name=Environment,Value=${ENVIRONMENT}},{Name=Application,Value=Authentication},{Name=IsTest,Value=false},{Name=SmsDestinationType,Value=${SMS_TYPE}},{Name=LogGroup,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceName,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceType,Value=AWS::Lambda::Function}]"
    echo "${METRIC_NAME} metric data sent successfully!"
    # Continue to alarm monitoring (don't return early)
  fi

  # Only send SMS count metrics for quota warning alarms
  if [[ ${METRIC_NAME} == "DomesticSmsQuotaEarlyWarning" || ${METRIC_NAME} == "InternationalSmsQuotaEarlyWarning" ]]; then
    echo "Sending ${sms_count_metric} metric with value ${test_value} (threshold: ${THRESHOLD})"
    aws cloudwatch put-metric-data \
      --namespace "${NAMESPACE}" \
      --metric-data "MetricName=${sms_count_metric},Value=${test_value},Unit=Count,Dimensions=[{Name=Environment,Value=${ENVIRONMENT}},{Name=Application,Value=Authentication},{Name=LogGroup,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceName,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceType,Value=AWS::Lambda::Function}]"
    echo "${sms_count_metric} metric data sent successfully!"
    echo "Waiting for scheduled SMS quota monitor lambda to process metrics (runs every 1 minute)..."
  fi

  # Verify metrics
  echo "Waiting 30 seconds for metrics to be processed..."
  sleep 30

  if [[ ${METRIC_NAME} == "DomesticSmsQuotaEarlyWarning" || ${METRIC_NAME} == "InternationalSmsQuotaEarlyWarning" ]]; then
    echo "Checking SMS count metric value..."
    metric_value=$(aws cloudwatch get-metric-statistics \
      --namespace "${NAMESPACE}" \
      --metric-name "${sms_count_metric}" \
      --dimensions Name=Environment,Value="${ENVIRONMENT}" Name=Application,Value=Authentication Name=LogGroup,Value="${ENVIRONMENT}"-email-notification-sqs-lambda Name=ServiceName,Value="${ENVIRONMENT}"-email-notification-sqs-lambda Name=ServiceType,Value=AWS::Lambda::Function \
      --start-time "$(date -u -v-5M +%Y-%m-%dT%H:%M:%S)" \
      --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
      --period 300 \
      --statistics Sum \
      --query "Datapoints[0].Sum" --output text)

    if [[ ${metric_value} != "None" && -n ${metric_value} ]]; then
      echo "Current ${sms_count_metric} value: ${metric_value}"
    else
      echo "${sms_count_metric} metric not yet available"
    fi

    echo "Checking warning metric value (generated by lambda)..."
    warning_value=$(aws cloudwatch get-metric-statistics \
      --namespace "${NAMESPACE}" \
      --metric-name "${METRIC_NAME}" \
      --dimensions Name=Environment,Value="${ENVIRONMENT}" \
      --start-time "$(date -u -v-5M +%Y-%m-%dT%H:%M:%S)" \
      --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
      --period 300 \
      --statistics Maximum \
      --query "Datapoints[0].Maximum" --output text)

    if [[ ${warning_value} != "None" && -n ${warning_value} ]]; then
      echo "Current ${METRIC_NAME} value: ${warning_value}"
    else
      echo "${METRIC_NAME} metric not yet available (lambda may still be processing)"
    fi
  else
    echo "Checking metric value..."
    metric_value=$(aws cloudwatch get-metric-statistics \
      --namespace "${NAMESPACE}" \
      --metric-name "${METRIC_NAME}" \
      --dimensions Name=Environment,Value="${ENVIRONMENT}" Name=Application,Value=Authentication Name=IsTest,Value=false Name=SmsDestinationType,Value="${SMS_TYPE}" \
      --start-time "$(date -u -v-5M +%Y-%m-%dT%H:%M:%S)" \
      --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
      --period 60 \
      --statistics Sum \
      --query "Datapoints[0].Sum" --output text)

    if [[ ${metric_value} != "None" && -n ${metric_value} ]]; then
      echo "Current metric value: ${metric_value}"
    else
      echo "Metric value not yet available (may take a few minutes to appear)"
    fi
  fi

  # Wait for alarm
  while true; do
    echo "Waiting 60 seconds for alarm evaluation..."
    sleep 60

    echo "Checking alarm state after metric..."
    new_state=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].StateValue" --output text)
    echo "New alarm state: ${new_state}"

    if [[ ${new_state} == "ALARM" ]]; then
      echo "✅ SUCCESS: Alarm triggered as expected!"

      # Wait for a slightly extended time to try and get this negative value in the next time period/"bucket" for easier visualisation in the AWS Console
      echo "Waiting 180 seconds until sending the negative value..."
      sleep 180

      # For early warning alarms, send negative value to bring total below threshold
      if [[ ${METRIC_NAME} == "DomesticSmsQuotaEarlyWarning" || ${METRIC_NAME} == "InternationalSmsQuotaEarlyWarning" ]]; then
        local deactivate_value=$((-(THRESHOLD + 100)))
        echo "Sending negative ${sms_count_metric} value ${deactivate_value} to deactivate alarm..."
        aws cloudwatch put-metric-data \
          --namespace "${NAMESPACE}" \
          --metric-data "MetricName=${sms_count_metric},Value=${deactivate_value},Unit=Count,Dimensions=[{Name=Environment,Value=${ENVIRONMENT}},{Name=Application,Value=Authentication},{Name=LogGroup,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceName,Value=${ENVIRONMENT}-email-notification-sqs-lambda},{Name=ServiceType,Value=AWS::Lambda::Function}]"
        echo "Deactivation metrics sent. Scheduled lambda will process on next run (every 1 minute)."
      elif [[ ${METRIC_NAME} == "SmsLimitExceeded" ]]; then
        echo "Limit exceeded alarm will auto-deactivate when no new 429 (rate limit exceeded) responses occur (treat_missing_data=notBreaching)."
        echo "Waiting for alarm to deactivate naturally..."
      fi

      # Wait for alarm deactivation
      if [[ ${METRIC_NAME} == "DomesticSmsQuotaEarlyWarning" || ${METRIC_NAME} == "InternationalSmsQuotaEarlyWarning" || ${METRIC_NAME} == "SmsLimitExceeded" ]]; then
        echo "Monitoring alarm deactivation..."
        local deactivation_wait_count=0
        while [[ ${deactivation_wait_count} -lt 25 ]]; do
          sleep 60
          deactivation_wait_count=$((deactivation_wait_count + 1))
          echo "Checking alarm state (attempt ${deactivation_wait_count}/25)..."
          local current_alarm_state
          current_alarm_state=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].StateValue" --output text)
          echo "Current alarm state: ${current_alarm_state}"

          if [[ ${current_alarm_state} == "OK" ]]; then
            echo "✅ SUCCESS: Alarm deactivated successfully!"
            break
          elif [[ ${deactivation_wait_count} -eq 25 ]]; then
            echo "⚠️  Alarm has not deactivated after 25 minutes. This may be normal for some alarm types."
          fi
        done
      fi
      break
    else
      echo "⏳ Alarm has not activated yet (Current state: ${new_state})"
      read -rp "Wait another 60 seconds? (y/n): " wait_more
      if [[ ${wait_more} != "y" && ${wait_more} != "Y" ]]; then
        echo "❌ FAILURE: Alarm did not trigger. Expected: ALARM, Got: ${new_state}"
        break
      fi
    fi
  done

  # Show alarm history
  echo -e "\nRecent alarm history:"
  aws cloudwatch describe-alarm-history \
    --alarm-name "${ALARM_NAME}" \
    --max-records 3 \
    --query "AlarmHistoryItems[*].[Timestamp,HistorySummary]" \
    --output table

  echo ""
  if [[ -n ${EMAIL_ADDRESSES} ]]; then
    echo "📧 Expect email notifications at:${EMAIL_ADDRESSES}"
  fi
}

# Show Info functionality
show_info() {
  local topic_arn subscription_count
  local -a topics=()

  setup_aws
  init_alarms

  echo "📧 SNS Topic Subscriptions (Environment: ${ENVIRONMENT:-none})"
  echo "============================================================="

  if [[ ${#ALARMS[@]} -eq 0 ]]; then
    echo "❌ No alarms found for environment: ${ENVIRONMENT}"
    echo "Cannot display SNS topic information without alarms."
    return
  fi

  for alarm_name in "${!ALARMS[@]}"; do
    local alarm_topics
    alarm_topics=$(aws cloudwatch describe-alarms --alarm-names "${alarm_name}" --query "MetricAlarms[0].AlarmActions" --output text)
    if [[ -n ${alarm_topics} && ${alarm_topics} != "None" ]]; then
      for topic_arn in ${alarm_topics}; do
        if [[ ! " ${topics[*]} " =~ ${topic_arn} ]]; then
          topics+=("${topic_arn}")
        fi
      done
    fi
  done

  for topic_arn in "${topics[@]}"; do
    echo "Topic: ${topic_arn}"
    subscription_count=$(aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "length(Subscriptions)" --output text 2> /dev/null || echo "0")

    if [[ ${subscription_count} -eq 0 ]]; then
      echo "⚠️  No subscriptions found!"
    else
      echo "Subscriptions (${subscription_count}):"
      aws sns list-subscriptions-by-topic --topic-arn "${topic_arn}" --query "Subscriptions[*].[Protocol,Endpoint,SubscriptionArn]" --output table
    fi
    echo ""
  done

  echo "🚨 Alarm States (Environment: ${ENVIRONMENT:-none})"
  echo "================================================="

  for alarm_name in "${!ALARMS[@]}"; do
    local state reason updated metric_name metric_value
    state=$(aws cloudwatch describe-alarms --alarm-names "${alarm_name}" --query "MetricAlarms[0].StateValue" --output text 2> /dev/null || echo "NOT_FOUND")

    if [[ ${state} == "NOT_FOUND" ]]; then
      echo "❓ ${alarm_name}: NOT FOUND"
    else
      reason=$(aws cloudwatch describe-alarms --alarm-names "${alarm_name}" --query "MetricAlarms[0].StateReason" --output text)
      updated=$(aws cloudwatch describe-alarms --alarm-names "${alarm_name}" --query "MetricAlarms[0].StateUpdatedTimestamp" --output text)
      metric_name=$(aws cloudwatch describe-alarms --alarm-names "${alarm_name}" --query "MetricAlarms[0].MetricName" --output text)

      case "${state}" in
        "OK") echo "✅ ${alarm_name}: ${state}" ;;
        "ALARM") echo "🔴 ${alarm_name}: ${state}" ;;
        "INSUFFICIENT_DATA") echo "⚠️  ${alarm_name}: ${state}" ;;
        *) echo "❓ ${alarm_name}: ${state}" ;;
      esac
      echo "   Reason: ${reason}"
      echo "   Updated: ${updated}"

      # Get current metric value for quota warning alarms
      if [[ ${metric_name} == "DomesticSmsQuotaEarlyWarning" || ${metric_name} == "InternationalSmsQuotaEarlyWarning" ]]; then
        metric_value=$(aws cloudwatch get-metric-statistics \
          --namespace "Authentication" \
          --metric-name "${metric_name}" \
          --dimensions Name=Environment,Value="${ENVIRONMENT}" \
          --start-time "$(date -u -v-10M +%Y-%m-%dT%H:%M:%S)" \
          --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
          --period 60 \
          --statistics Maximum \
          --query "Datapoints[-1].Maximum" --output text 2> /dev/null || echo "None")

        if [[ ${metric_value} != "None" && -n ${metric_value} ]]; then
          echo "   Current ${metric_name} value: ${metric_value}"
        else
          echo "   Current ${metric_name} value: No recent data"
        fi
      fi
    fi
    echo ""
  done
}

main() {
  local choice

  # If environment provided as argument, use it
  if [[ $# -eq 1 ]]; then
    ENVIRONMENT="$1"
    [[ " ${ENVIRONMENTS[*]} " =~ ${ENVIRONMENT} ]] || {
      echo "Error: invalid environment specified: ${ENVIRONMENT}"
      echo "Valid environments are: ${ENVIRONMENTS[*]}"
      exit 1
    }
  fi

  while true; do
    show_main_menu
    read -rp "Select option (1-6): " choice

    case "${choice}" in
      1)
        select_environment
        echo "Environment: ${ENVIRONMENT}"
        sns_subscribe
        ;;
      2)
        select_environment
        echo "Environment: ${ENVIRONMENT}"
        sns_unsubscribe
        ;;
      3)
        select_environment
        echo "Environment: ${ENVIRONMENT}"
        test_alarm
        ;;
      4)
        select_environment
        echo "Environment: ${ENVIRONMENT}"
        show_info
        ;;
      5)
        ENVIRONMENT=""
        select_environment
        echo "Environment changed to: ${ENVIRONMENT}"
        ;;
      6)
        echo "Goodbye!"
        exit 0
        ;;
      *)
        echo "Invalid option. Please select 1-6."
        ;;
    esac

    echo ""
    read -rp "Press Enter to continue..."
  done
}

main "$@"
