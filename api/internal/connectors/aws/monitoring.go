package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/ponack/touchstone/internal/connectors"
)

// scanCloudWatchMonitoring builds the evidence chain CIS Section 4
// asks about: a CloudWatch metric filter on a log group, an alarm
// watching that metric, and an SNS topic with at least one
// subscription receiving the alarm.
//
// Strategy: enumerate metric filters per region (the filter pattern
// is the unique signal we can match by token). For each filter, look
// up the alarm(s) watching its metric (namespace + name). For each
// such alarm, check whether any of its SNS-topic actions has at
// least one active subscription. The full chain is pre-computed
// into one aws.cloudwatch.metric_filter resource per filter so the
// rego only inspects scalar / string attrs.
func scanCloudWatchMonitoring(ctx context.Context, awsCfg aws.Config, regions []string) ([]connectors.Resource, error) {
	if len(regions) == 0 {
		regions = []string{defaultRegion}
	}

	var out []connectors.Resource
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		cwl := cloudwatchlogs.NewFromConfig(regionCfg)
		cw := cloudwatch.NewFromConfig(regionCfg)
		snsClient := sns.NewFromConfig(regionCfg)

		filters, err := listMetricFilters(ctx, cwl)
		if err != nil {
			slog.Warn("cloudwatchlogs DescribeMetricFilters failed", "region", region, "err", err)
			continue
		}
		if len(filters) == 0 {
			continue
		}

		// Cache the alarms once per region — every filter walks the
		// same list.
		alarms, err := listMetricAlarms(ctx, cw)
		if err != nil {
			slog.Warn("cloudwatch DescribeAlarms failed", "region", region, "err", err)
			alarms = nil
		}

		// SNS topic → has-subscription cache scoped to this region.
		subCache := map[string]bool{}

		for _, f := range filters {
			for _, mt := range f.MetricTransformations {
				ns := aws.ToString(mt.MetricNamespace)
				name := aws.ToString(mt.MetricName)
				topic, hasAlarm := findAlarmAction(alarms, ns, name)
				hasSub := false
				if topic != "" {
					if cached, ok := subCache[topic]; ok {
						hasSub = cached
					} else {
						hasSub = topicHasSubscriptions(ctx, snsClient, topic)
						subCache[topic] = hasSub
					}
				}
				out = append(out, connectors.Resource{
					Type: "aws.cloudwatch.metric_filter",
					ID:   "aws-cwl://" + region + "/log-groups/" + aws.ToString(f.LogGroupName) + "/filters/" + aws.ToString(f.FilterName),
					Attrs: map[string]any{
						"filter_name":             aws.ToString(f.FilterName),
						"log_group_name":          aws.ToString(f.LogGroupName),
						"filter_pattern":          aws.ToString(f.FilterPattern),
						"metric_namespace":        ns,
						"metric_name":             name,
						"region":                  region,
						"has_alarm":               hasAlarm,
						"alarm_topic_arn":         topic,
						"has_active_subscription": hasSub,
					},
				})
			}
		}
	}
	return out, nil
}

func listMetricFilters(ctx context.Context, client *cloudwatchlogs.Client) ([]cwltypes.MetricFilter, error) {
	var out []cwltypes.MetricFilter
	pager := cloudwatchlogs.NewDescribeMetricFiltersPaginator(client, &cloudwatchlogs.DescribeMetricFiltersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.MetricFilters...)
	}
	return out, nil
}

func listMetricAlarms(ctx context.Context, client *cloudwatch.Client) ([]cwtypes.MetricAlarm, error) {
	var out []cwtypes.MetricAlarm
	pager := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm},
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.MetricAlarms...)
	}
	return out, nil
}

// findAlarmAction returns (snsTopicArn, hasAlarm) for the first
// alarm watching the supplied namespace + metric name. The first
// SNS-shaped alarm action is returned — CIS only cares whether at
// least one notification path exists, not all of them.
func findAlarmAction(alarms []cwtypes.MetricAlarm, namespace, name string) (string, bool) {
	for _, a := range alarms {
		if aws.ToString(a.Namespace) != namespace {
			continue
		}
		if aws.ToString(a.MetricName) != name {
			continue
		}
		for _, action := range a.AlarmActions {
			if len(action) > 8 && action[:8] == "arn:aws:" {
				return action, true
			}
		}
		// Alarm exists but has no SNS action — still report hasAlarm=true
		// so the rule can distinguish "no alarm" from "alarm with no
		// notification".
		return "", true
	}
	return "", false
}

func topicHasSubscriptions(ctx context.Context, client *sns.Client, topicARN string) bool {
	pager := sns.NewListSubscriptionsByTopicPaginator(client, &sns.ListSubscriptionsByTopicInput{
		TopicArn: aws.String(topicARN),
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			slog.Warn("sns ListSubscriptionsByTopic failed", "topic", topicARN, "err", err)
			return false
		}
		for _, s := range page.Subscriptions {
			// PendingConfirmation subscriptions don't deliver — exclude.
			if aws.ToString(s.SubscriptionArn) == "PendingConfirmation" {
				continue
			}
			return true
		}
	}
	return false
}
