#!/usr/bin/env bash
set -euo pipefail

readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
readonly -a ENVIRONMENTS=("authdev1" "authdev2" "authdev3" "dev")

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
    if [[ -n "${ENVIRONMENT:-}" ]]; then
        return
    fi
    
    echo ""
    echo "Environment Selection (Current: ${ENVIRONMENT:-none})"
    echo "===================================================="
    echo "Available environments:"
    for i in "${!ENVIRONMENTS[@]}"; do
        echo "$((i+1)). ${ENVIRONMENTS[i]}"
    done
    echo ""
    read -p "Select environment (1-${#ENVIRONMENTS[@]}): " selection
    
    [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le "${#ENVIRONMENTS[@]}" ]] || {
        echo "Error: Invalid selection"
        exit 1
    }
    
    ENVIRONMENT="${ENVIRONMENTS[$((selection-1))]}"
}

setup_aws() {
    if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
        export AWS_PROFILE="di-auth-development-admin"
    else
        export AWS_PROFILE="gds-di-development-admin"
    fi
    source "${DIR}/../export_aws_creds.sh"
}

# SNS Subscribe functionality
sns_subscribe() {
    local email topic_arn account_id existing needs_confirmation subscription_output
    
    read -p "Enter email address to subscribe: " email
    
    setup_aws
    
    if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
        account_id="653994557586"
    else
        account_id="216552277552"
    fi
    
    topic_arn="arn:aws:sns:eu-west-2:${account_id}:${ENVIRONMENT}-slack-events"
    
    echo "Checking for existing subscriptions..."
    existing=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "Subscriptions[?Endpoint=='$email'].SubscriptionArn" --output text)
    needs_confirmation=false
    
    if [[ -n "$existing" ]]; then
        echo "Subscription already exists for $email:"
        echo "$existing"
        
        if [[ "$existing" == "PendingConfirmation" ]]; then
            echo "Subscription is pending confirmation."
            needs_confirmation=true
        else
            echo "Subscription is already confirmed."
        fi
        echo "Skipping subscription creation."
    else
        echo "Creating subscription to $topic_arn for $email..."
        
        subscription_output=$(aws sns subscribe \
            --topic-arn "$topic_arn" \
            --protocol email \
            --notification-endpoint "$email")
        
        echo "Subscription created successfully!"
        echo "$subscription_output"
        needs_confirmation=true
    fi
    
    echo -e "\nListing subscription details:"
    aws sns list-subscriptions-by-topic --topic-arn "$topic_arn"
    
    if [[ "$needs_confirmation" == "true" ]]; then
        echo -e "\nA confirmation email has been sent to $email"
        echo "Please check your email and click the confirmation link."
        read -p "Press Enter after clicking the confirmation link..."
        
        echo -e "\nUpdated subscription details:"
        aws sns list-subscriptions-by-topic --topic-arn "$topic_arn"
    else
        echo -e "\nNo confirmation needed - subscription is already active."
    fi
}

# SNS Unsubscribe functionality
sns_unsubscribe() {
    local email topic_arn account_id existing
    
    read -p "Enter email address to unsubscribe: " email
    
    setup_aws
    
    if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
        account_id="653994557586"
    else
        account_id="216552277552"
    fi
    
    topic_arn="arn:aws:sns:eu-west-2:${account_id}:${ENVIRONMENT}-slack-events"
    
    echo "Checking for existing subscriptions..."
    existing=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "Subscriptions[?Endpoint=='$email'].SubscriptionArn" --output text)
    
    if [[ -z "$existing" ]]; then
        echo "No subscription found for $email"
        echo "Nothing to unsubscribe."
    else
        echo "Found subscription for $email:"
        echo "$existing"
        
        if [[ "$existing" == "PendingConfirmation" ]]; then
            echo "Subscription is pending confirmation - cannot unsubscribe pending subscriptions."
            echo "Pending subscriptions will automatically expire if not confirmed."
        else
            echo "Unsubscribing $email from $topic_arn..."
            aws sns unsubscribe --subscription-arn "$existing"
            echo "Unsubscribed successfully!"
        fi
    fi
    
    echo -e "\nRemaining subscription details:"
    aws sns list-subscriptions-by-topic --topic-arn "$topic_arn"
}

# Test Alarm functionality
init_alarms() {
    ALARMS["${ENVIRONMENT}-domestic-sms-quota-warning"]="DomesticSmsSent:Authentication:300000:DOMESTIC"
    ALARMS["${ENVIRONMENT}-international-sms-quota-warning"]="InternationalSmsSent:Authentication:4000:INTERNATIONAL"
    ALARMS["${ENVIRONMENT}-domestic-sms-limit-exceeded-alarm"]="SmsLimitExceeded:Authentication:2:DOMESTIC"
    ALARMS["${ENVIRONMENT}-international-sms-limit-exceeded-alarm"]="SmsLimitExceeded:Authentication:2:INTERNATIONAL"
}

select_alarm() {
    local -a alarm_names sorted_alarms
    local i selection
    
    for alarm_name in "${!ALARMS[@]}"; do
        alarm_names+=("$alarm_name")
    done
    
    IFS=$'\n' sorted_alarms=($(sort <<<"${alarm_names[*]}"))
    unset IFS
    
    echo ""
    echo "Alarm Selection (Environment: ${ENVIRONMENT:-none})"
    echo "================================================="
    echo "Available alarms to test:"
    for i in "${!sorted_alarms[@]}"; do
        echo "$((i+1)). ${sorted_alarms[i]}"
    done
    
    echo ""
    read -p "Select alarm to test (1-${#sorted_alarms[@]}): " selection
    
    [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -le "${#sorted_alarms[@]}" ]] || {
        echo "Error: Invalid selection"
        exit 1
    }
    
    ALARM_NAME="${sorted_alarms[$((selection-1))]}"
    echo "Selected alarm: ${ALARM_NAME}"
    
    IFS=':' read -r METRIC_NAME NAMESPACE THRESHOLD SMS_TYPE <<< "${ALARMS[$ALARM_NAME]}"
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
    if [[ -n "$alarm_actions" && "$alarm_actions" != "None" ]]; then
        for topic_arn in $alarm_actions; do
            echo "SNS Topic: $topic_arn"
            subscription_count=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "length(Subscriptions)" --output text)
            
            if [[ "$subscription_count" -eq 0 ]]; then
                echo "⚠️  No subscriptions found!"
            else
                echo "📧 Subscriptions ($subscription_count):"
                aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "Subscriptions[*].[Protocol,Endpoint]" --output table
                
                emails=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "Subscriptions[?Protocol=='email'].Endpoint" --output text)
                if [[ -n "$emails" ]]; then
                    EMAIL_ADDRESSES="${EMAIL_ADDRESSES} ${emails}"
                fi
            fi
            echo ""
        done
    else
        echo "⚠️  WARNING: Alarm has no SNS actions configured!"
        echo ""
    fi
    
    read -p "Proceed with alarm test? (y/n): " proceed
    if [[ "$proceed" != "y" && "$proceed" != "Y" ]]; then
        echo "Test cancelled."
        return
    fi
    
    # Check alarm state
    echo "Checking current alarm state..."
    current_state=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].StateValue" --output text)
    echo "Current alarm state: ${current_state}"
    
    if [[ "${current_state}" == "ALARM" ]]; then
        echo "⚠️  Alarm is already in ALARM state! Cannot test."
        echo ""
        echo "Alarm details:"
        aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].[AlarmName,StateValue,StateReason,StateUpdatedTimestamp]" --output table
        return
    fi
    
    # Send test metric
    test_value=$((THRESHOLD + 100))
    echo "Sending metric data: ${test_value} (threshold: ${THRESHOLD})"
    aws cloudwatch put-metric-data \
        --namespace "${NAMESPACE}" \
        --metric-data MetricName="${METRIC_NAME}",Value="${test_value}",Unit=Count,Dimensions="[{Name=Environment,Value=${ENVIRONMENT}},{Name=SmsDestinationType,Value=${SMS_TYPE}}]"
    echo "Metric data sent successfully!"
    
    # Verify metric
    echo "Waiting 30 seconds for metric to be processed..."
    sleep 30
    
    echo "Checking metric value..."
    metric_value=$(aws cloudwatch get-metric-statistics \
        --namespace "${NAMESPACE}" \
        --metric-name "${METRIC_NAME}" \
        --dimensions Name=Environment,Value="${ENVIRONMENT}" Name=SmsDestinationType,Value="${SMS_TYPE}" \
        --start-time "$(date -u -v-5M +%Y-%m-%dT%H:%M:%S)" \
        --end-time "$(date -u +%Y-%m-%dT%H:%M:%S)" \
        --period 300 \
        --statistics Sum \
        --query "Datapoints[0].Sum" --output text)
    
    if [[ "$metric_value" != "None" && -n "$metric_value" ]]; then
        echo "Current metric value: ${metric_value}"
    else
        echo "Metric value not yet available (may take a few minutes to appear)"
    fi
    
    # Wait for alarm
    while true; do
        echo "Waiting 60 seconds for alarm evaluation..."
        sleep 60
        
        echo "Checking alarm state after metric..."
        new_state=$(aws cloudwatch describe-alarms --alarm-names "${ALARM_NAME}" --query "MetricAlarms[0].StateValue" --output text)
        echo "New alarm state: ${new_state}"
        
        if [[ "${new_state}" == "ALARM" ]]; then
            echo "✅ SUCCESS: Alarm triggered as expected!"
            break
        else
            echo "⏳ Alarm has not activated yet (Current state: ${new_state})"
            read -p "Wait another 60 seconds? (y/n): " wait_more
            if [[ "$wait_more" != "y" && "$wait_more" != "Y" ]]; then
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
    if [[ -n "$EMAIL_ADDRESSES" ]]; then
        echo "📧 Expect email notifications at:${EMAIL_ADDRESSES}"
    fi
}

# Show Info functionality
show_info() {
    local account_id topic_arn subscription_count
    local -a topics=("${ENVIRONMENT}-slack-events" "${ENVIRONMENT}-auth-pagerduty-alerts")
    local -a alarm_names=()
    
    setup_aws
    
    echo "📧 SNS Topic Subscriptions (Environment: ${ENVIRONMENT:-none})"
    echo "============================================================="
    
    if [[ ${ENVIRONMENT} =~ ^authdev ]]; then
        account_id="653994557586"
    else
        account_id="216552277552"
    fi
    
    for topic_name in "${topics[@]}"; do
        topic_arn="arn:aws:sns:eu-west-2:${account_id}:${topic_name}"
        
        echo "Topic: $topic_arn"
        subscription_count=$(aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "length(Subscriptions)" --output text 2>/dev/null || echo "0")
        
        if [[ "$subscription_count" -eq 0 ]]; then
            echo "⚠️  No subscriptions found!"
        else
            echo "Subscriptions ($subscription_count):"
            aws sns list-subscriptions-by-topic --topic-arn "$topic_arn" --query "Subscriptions[*].[Protocol,Endpoint,SubscriptionArn]" --output table
        fi
        echo ""
    done
    
    echo "🚨 Alarm States (Environment: ${ENVIRONMENT:-none})"
    echo "================================================="
    
    alarm_names+=(
        "${ENVIRONMENT}-domestic-sms-quota-warning"
        "${ENVIRONMENT}-international-sms-quota-warning"
        "${ENVIRONMENT}-domestic-sms-limit-exceeded-alarm"
        "${ENVIRONMENT}-international-sms-limit-exceeded-alarm"
    )
    
    for alarm_name in "${alarm_names[@]}"; do
        local state reason updated
        state=$(aws cloudwatch describe-alarms --alarm-names "$alarm_name" --query "MetricAlarms[0].StateValue" --output text 2>/dev/null || echo "NOT_FOUND")
        
        if [[ "$state" == "NOT_FOUND" ]]; then
            echo "❓ $alarm_name: NOT FOUND"
        else
            reason=$(aws cloudwatch describe-alarms --alarm-names "$alarm_name" --query "MetricAlarms[0].StateReason" --output text)
            updated=$(aws cloudwatch describe-alarms --alarm-names "$alarm_name" --query "MetricAlarms[0].StateUpdatedTimestamp" --output text)
            
            case "$state" in
                "OK") echo "✅ $alarm_name: $state" ;;
                "ALARM") echo "🔴 $alarm_name: $state" ;;
                "INSUFFICIENT_DATA") echo "⚠️  $alarm_name: $state" ;;
                *) echo "❓ $alarm_name: $state" ;;
            esac
            echo "   Reason: $reason"
            echo "   Updated: $updated"
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
        read -p "Select option (1-6): " choice
        
        case "$choice" in
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
        read -p "Press Enter to continue..."
    done
}

main "$@"