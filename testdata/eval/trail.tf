resource "aws_cloudtrail" "good" {
  name                          = "eval-good"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
}

resource "aws_cloudtrail" "single_region" {
  name                          = "eval-single_region"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
}

resource "aws_cloudtrail" "no_validation" {
  name                          = "eval-no_validation"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = false
  kms_key_id                    = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
}

resource "aws_cloudtrail" "no_kms" {
  name                          = "eval-no_kms"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}

resource "aws_cloudtrail" "weak" {
  name                          = "eval-weak"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}
