// Package live implements the "live mode" collector that inventories an AWS
// account through read-only API calls instead of Terraform state. v0.9.0-rc1
// covers S3 only: buckets, their regions, and their public-access posture.
// The mapping is deliberately the same normalized tfstate.Resource shape the
// Terraform and CloudTrail collectors produce, so downstream analyzers run
// unchanged.
package live

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

// Options configures the live collector. The role in docs/iam-policy.json is
// read-only; inventory is the goal, never a change.
type Options struct {
	// RoleARN is an optional read-only role to assume before scanning.
	RoleARN string

	// Regions is kept for API compatibility with the file collectors; the S3
	// ListBuckets API is account-global, so v0.9.0-rc1 scans one region.
	Regions []string

	// EndpointURL overrides the AWS service endpoint (LocalStack and other
	// compatible emulators). Production use leaves it empty.
	EndpointURL string

	// Region pins the client's signing region; the collector defaults to
	// us-east-1 and derives per-bucket regions from GetBucketLocation.
	Region string

	// StaticCredentials is used by emulators that accept any key pair.
	AccessKeyID     string
	SecretAccessKey string
}

// ErrNotImplemented is returned for inputs outside the v0.9.0-rc1 scope
// (anything that is not an S3 inventory).
var ErrNotImplemented = fmt.Errorf("live mode: not implemented")

// Collector inventories an AWS account live, read-only.
type Collector interface {
	Collect(ctx context.Context) ([]tfstate.Resource, error)
}

// NewCollector returns the S3 live collector.
func NewCollector(opts Options) Collector {
	return &s3Collector{opts: opts}
}

type s3Collector struct {
	opts Options
}

// Collect inventories every bucket in the account and its public-access
// posture. Any permission failure is returned as an error: a partial list
// must never masquerade as a complete, healthy inventory.
func (c *s3Collector) Collect(ctx context.Context) ([]tfstate.Resource, error) {
	client, err := newS3Client(ctx, c.opts)
	if err != nil {
		return nil, err
	}

	// ListBuckets is account-global; the paginator handles the continuation
	// tokens the API can return for large accounts.
	var names []string
	pager := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}
		for _, b := range page.Buckets {
			names = append(names, aws.ToString(b.Name))
		}
	}

	// Bucket-level calls are regional, so cache one client per discovered
	// region and address each bucket through its own region's client.
	clients := map[string]*s3.Client{"us-east-1": client}
	regional := func(region string) (*s3.Client, error) {
		if rc, ok := clients[region]; ok {
			return rc, nil
		}
		opts := c.opts
		opts.Region = region
		rc, err := newS3Client(ctx, opts)
		if err != nil {
			return nil, err
		}
		clients[region] = rc
		return rc, nil
	}

	var resources []tfstate.Resource
	for _, name := range names {
		region, err := bucketRegion(ctx, client, name)
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", name, err)
		}
		resources = append(resources, tfstate.Resource{
			Address:    "aws_s3_bucket." + name,
			Type:       "aws_s3_bucket",
			Name:       name,
			Attributes: map[string]any{"bucket": name, "region": region},
		})

		rc, err := regional(region)
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", name, err)
		}
		pab, err := publicAccessBlock(ctx, rc, name)
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", name, err)
		}
		policy, err := bucketPolicy(ctx, rc, name)
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", name, err)
		}
		lifecycle, err := bucketLifecycle(ctx, rc, name)
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", name, err)
		}
		if pab != nil {
			// Only a configuration that exists is evidence. A missing
			// configuration is a coverage gap, not proof of exposure.
			attrs := map[string]any{
				"bucket":                  name,
				"block_public_acls":       aws.ToBool(pab.BlockPublicAcls),
				"block_public_policy":     aws.ToBool(pab.BlockPublicPolicy),
				"ignore_public_acls":      aws.ToBool(pab.IgnorePublicAcls),
				"restrict_public_buckets": aws.ToBool(pab.RestrictPublicBuckets),
			}
			resources = append(resources, tfstate.Resource{
				Address:    "aws_s3_bucket_public_access_block." + name,
				Type:       "aws_s3_bucket_public_access_block",
				Name:       name,
				Attributes: attrs,
			})
		}

		// The bucket policy feeds the TLS rule: a bucket with no policy
		// genuinely does not deny HTTP, which the rule reports as-is. A
		// missing policy is therefore not an error, only absent evidence.
		if policy != "" {
			resources = append(resources, tfstate.Resource{
				Address:    "aws_s3_bucket_policy." + name,
				Type:       "aws_s3_bucket_policy",
				Name:       name,
				Attributes: map[string]any{"bucket": name, "policy": policy},
			})
		}
		if lifecycle != nil {
			resources = append(resources, tfstate.Resource{
				Address:    "aws_s3_bucket_lifecycle_configuration." + name,
				Type:       "aws_s3_bucket_lifecycle_configuration",
				Name:       name,
				Attributes: map[string]any{"bucket": name, "lifecycle_rule": lifecycle},
			})
		}
	}
	return resources, nil
}

// bucketLifecycle returns the bucket's lifecycle rules as normalized blocks,
// or nil when the bucket has none. A bucket without lifecycle rules genuinely
// never moves objects to cheaper storage classes, so the cost rule's finding
// is true and no error is hidden.
func bucketLifecycle(ctx context.Context, client *s3.Client, name string) ([]any, error) {
	out, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(name)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchLifecycleConfiguration" {
			return nil, nil
		}
		return nil, err
	}
	rules := make([]any, 0, len(out.Rules))
	for _, r := range out.Rules {
		rule := map[string]any{"status": string(r.Status)}
		if r.ID != nil {
			rule["id"] = aws.ToString(r.ID)
		}
		var transitions []any
		for _, t := range r.Transitions {
			tr := map[string]any{"storage_class": string(t.StorageClass)}
			if t.Days != nil {
				tr["days"] = *t.Days
			}
			transitions = append(transitions, tr)
		}
		if len(transitions) > 0 {
			rule["transitions"] = transitions
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// bucketPolicy returns the bucket policy document, or "" when the bucket has
// none.
func bucketPolicy(ctx context.Context, client *s3.Client, name string) (string, error) {
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(name)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
			return "", nil
		}
		return "", err
	}
	return aws.ToString(out.Policy), nil
}

// bucketRegion resolves the bucket's region, defaulting to us-east-1 when the
// API reports the empty location string (legacy buckets).
func bucketRegion(ctx context.Context, client *s3.Client, name string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(name)})
	if err != nil {
		return "", err
	}
	loc := string(out.LocationConstraint)
	if loc == "" {
		loc = "us-east-1"
	}
	return loc, nil
}

// publicAccessBlock returns the bucket's public-access-block configuration,
// or nil when the bucket has none configured.
func publicAccessBlock(ctx context.Context, client *s3.Client, name string) (*s3types.PublicAccessBlockConfiguration, error) {
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			// The bucket has no public-access-block configuration. That is a
			// coverage gap, not proof of exposure, so it must not become a
			// finding on its own.
			return nil, nil
		}
		return nil, err
	}
	return out.PublicAccessBlockConfiguration, nil
}

// newS3Client builds the S3 API client from the default credential chain,
// optionally assuming a read-only role, with an optional endpoint override.
// The AWS_ENDPOINT_URL environment variable is honored too, so emulators
// work through the CLI without extra flags.
func newS3Client(ctx context.Context, opts Options) (*s3.Client, error) {
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if opts.RoleARN != "" {
		if opts.AccessKeyID != "" || opts.SecretAccessKey != "" {
			return nil, fmt.Errorf("live: static credentials and --role-arn are mutually exclusive; the role must come from the ambient credential chain")
		}
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, opts.RoleARN)
	}
	var s3Opts []func(*s3.Options)
	endpoint := opts.EndpointURL
	if endpoint == "" {
		endpoint = os.Getenv("AWS_ENDPOINT_URL")
	}
	if endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		})
	}
	if opts.AccessKeyID != "" && opts.SecretAccessKey != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     opts.AccessKeyID,
					SecretAccessKey: opts.SecretAccessKey,
				}, nil
			})
		})
	}
	return s3.NewFromConfig(cfg, s3Opts...), nil
}
