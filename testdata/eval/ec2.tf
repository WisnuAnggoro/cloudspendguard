resource "aws_instance" "required" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_instance" "required_hop2" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_instance" "optional" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_instance" "unset" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

}

resource "aws_instance" "endpoint_only" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint = "enabled"
  }
}

resource "aws_instance" "no_imds" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint = "disabled"
  }
}
