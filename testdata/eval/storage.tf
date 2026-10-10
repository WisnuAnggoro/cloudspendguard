resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1a"
  size              = 50
  encrypted         = false
}

resource "aws_ebs_volume" "logs" {
  availability_zone = "eu-west-1a"
  size              = 50
  encrypted         = false
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 50
  encrypted         = true
}

resource "aws_ebs_volume" "backup" {
  availability_zone = "eu-west-1a"
  size              = 50
  encrypted         = true
  kms_key_id        = "arn:aws:kms:eu-west-1:111122223333:key/abcd"
}


variable "encrypt_volumes" {
  type    = bool
  default = false
}

resource "aws_ebs_volume" "param" {
  availability_zone = "eu-west-1a"
  size              = 20
  encrypted         = var.encrypt_volumes
}
