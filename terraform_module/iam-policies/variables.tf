variable "name" {
  description = "Name of the JSON policy file, minus the file extension. For example, 'result' instead of 'result.json'"
}

variable "region" {
  description = "The AWS region for these resources, such as us-east-1."
}

variable "description" {
  description = "The description to include for the IAM policy."
  default     = "Generated by Policy Sentry"
}

variable "policy_json" {
  description = "The policy document in json"
}
