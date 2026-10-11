resource "aws_efs_file_system" "shared" {
  encrypted = false
}

resource "aws_efs_file_system" "legacy" {
  creation_token = "legacy"
}

resource "aws_efs_file_system" "secure" {
  encrypted = true
}

resource "aws_efs_file_system" "secure_kms" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
}
