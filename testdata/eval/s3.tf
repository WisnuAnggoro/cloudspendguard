resource "aws_s3_bucket" "open_acls" {
  bucket = "eval-open_acls"
}

resource "aws_s3_bucket_public_access_block" "open_acls" {
  bucket                  = aws_s3_bucket.open_acls.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "open_all" {
  bucket = "eval-open_all"
}

resource "aws_s3_bucket_public_access_block" "open_all" {
  bucket                  = aws_s3_bucket.open_all.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "closed" {
  bucket = "eval-closed"
}

resource "aws_s3_bucket_public_access_block" "closed" {
  bucket                  = aws_s3_bucket.closed.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "closed2" {
  bucket = "eval-closed2"
}

resource "aws_s3_bucket_public_access_block" "closed2" {
  bucket                  = aws_s3_bucket.closed2.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
