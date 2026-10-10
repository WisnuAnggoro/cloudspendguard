resource "aws_kms_key" "rotating" {
  enable_key_rotation = true
}

resource "aws_kms_key" "static" {
  enable_key_rotation = false
}

resource "aws_kms_key" "default" {
  description = "no rotation setting"
}

resource "aws_kms_key" "signing" {
  customer_master_key_spec = "RSA_2048"
  key_usage = "SIGN_VERIFY"
  enable_key_rotation = false
}
