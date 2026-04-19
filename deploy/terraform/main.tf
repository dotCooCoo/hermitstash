# HermitStash — Terraform deployment
#
# Provisions a cloud VM and deploys HermitStash via Docker.
# Supports: DigitalOcean, AWS, Hetzner (swap provider block).
#
# Usage:
#   cd deploy/terraform
#   cp terraform.tfvars.example terraform.tfvars  # edit with your values
#   terraform init
#   terraform plan
#   terraform apply
#
# Default provider: DigitalOcean (cheapest for self-hosting)

terraform {
  required_version = ">= 1.5"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# ---- Variables ----

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "DigitalOcean region"
  type        = string
  default     = "nyc1"
}

variable "size" {
  description = "Droplet size (1GB RAM minimum)"
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "domain" {
  description = "Domain name for HermitStash (optional)"
  type        = string
  default     = ""
}

variable "ssh_key_fingerprint" {
  description = "SSH key fingerprint for access"
  type        = string
}

# ---- Provider ----

provider "digitalocean" {
  token = var.do_token
}

# ---- Droplet ----

resource "digitalocean_droplet" "hermitstash" {
  image    = "docker-20-04"
  name     = "hermitstash"
  region   = var.region
  size     = var.size
  ssh_keys = [var.ssh_key_fingerprint]

  user_data = <<-CLOUD_INIT
    #!/bin/bash
    set -euo pipefail

    # Create data directories
    mkdir -p /opt/hermitstash/data /opt/hermitstash/uploads

    # Run HermitStash
    docker run -d --name hermitstash \
      --restart unless-stopped \
      -p 3000:3000 \
      -v /opt/hermitstash/data:/app/data \
      -v /opt/hermitstash/uploads:/app/uploads \
      --shm-size=256m \
      -e TRUST_PROXY=true \
      -e RP_ORIGIN=${var.domain != "" ? "https://${var.domain}" : ""} \
      ghcr.io/dotcoocoo/hermitstash:1
  CLOUD_INIT

  tags = ["hermitstash", "self-hosted"]
}

# ---- Firewall ----

resource "digitalocean_firewall" "hermitstash" {
  name        = "hermitstash"
  droplet_ids = [digitalocean_droplet.hermitstash.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "3000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ---- DNS (optional) ----

resource "digitalocean_domain" "hermitstash" {
  count = var.domain != "" ? 1 : 0
  name  = var.domain
}

resource "digitalocean_record" "hermitstash_a" {
  count  = var.domain != "" ? 1 : 0
  domain = digitalocean_domain.hermitstash[0].id
  type   = "A"
  name   = "@"
  value  = digitalocean_droplet.hermitstash.ipv4_address
  ttl    = 300
}

# ---- Outputs ----

output "ip" {
  value       = digitalocean_droplet.hermitstash.ipv4_address
  description = "Droplet public IP"
}

output "url" {
  value       = var.domain != "" ? "https://${var.domain}" : "http://${digitalocean_droplet.hermitstash.ipv4_address}:3000"
  description = "HermitStash URL"
}

output "ssh" {
  value       = "ssh root@${digitalocean_droplet.hermitstash.ipv4_address}"
  description = "SSH command"
}
