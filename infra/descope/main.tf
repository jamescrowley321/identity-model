terraform {
  cloud {
    organization = "jamescrowley321"

    workspaces {
      name = "py-identity-model-dev"
    }
  }

  required_version = ">= 1.5"

  required_providers {
    descope = {
      source  = "jamescrowley321/descope"
      version = "~> 1.0"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}

provider "descope" {
  project_id = var.project_id
}

provider "github" {
  owner = "jamescrowley321"
}
