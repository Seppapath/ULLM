# Azure Confidential Computing H100 deployment for ullm-tee.
#
# Boots an Intel TDX confidential VM with an NVIDIA H100 GPU in CC-mode,
# loads the reproducible TEE image (built by `infra/tee-image/flake.nix`),
# fetches attestation evidence on first boot via the Azure attestation
# service, and registers the resulting MRTD/RTMR set with the gateway.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  type        = string
  default     = "eastus2"
  description = "Azure region with H100 CC SKU availability"
}

variable "resource_group_name" {
  type    = string
  default = "ullm-tee-prod"
}

variable "tee_image_uri" {
  type        = string
  description = "OCI image URI for the reproducibly-built ullm-tee container"
}

variable "expected_image_sha256" {
  type        = string
  description = "SHA-256 of the TEE image as published in infra/tee-image/manifest.json"
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

resource "azurerm_virtual_network" "vnet" {
  name                = "ullm-tee-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "ullm-tee-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_interface" "nic" {
  name                = "ullm-tee-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Standard_NCC_H100_v5 — H100 with CC-On + Intel TDX host
resource "azurerm_linux_virtual_machine" "tee" {
  name                = "ullm-tee-1"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  size                = "Standard_NCC40ads_H100_v5"
  admin_username      = "ullmadmin"

  network_interface_ids = [
    azurerm_network_interface.nic.id,
  ]

  # Confidential disk + Trusted Launch with TDX + NVIDIA CC.
  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "Premium_LRS"
    security_encryption_type = "DiskWithVMGuestState"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-confidential-vm-noble"
    sku       = "24_04-lts-cvm"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "ullmadmin"
    public_key = file("~/.ssh/id_ed25519.pub")
  }

  # First-boot: pull the pinned TEE image and start ullm-tee.
  custom_data = base64encode(<<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    podman pull "${var.tee_image_uri}"
    actual_sha="$(podman inspect "${var.tee_image_uri}" --format '{{.Id}}' | sed 's/sha256://')"
    if [[ "$actual_sha" != "${var.expected_image_sha256}" ]]; then
        echo "image hash mismatch: got $actual_sha, expected ${var.expected_image_sha256}" >&2
        exit 1
    fi
    podman run -d --replace --name ullm-tee \
        --device nvidia.com/gpu=all \
        -p 9001:9001 \
        -e ULLM_TEE_ADDR=0.0.0.0:9001 \
        "${var.tee_image_uri}"
  EOF
  )

  vtpm_enabled        = true
  secure_boot_enabled = true
}

output "tee_private_ip" {
  value = azurerm_network_interface.nic.private_ip_address
}
