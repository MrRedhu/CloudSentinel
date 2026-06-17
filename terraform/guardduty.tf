# GuardDuty detector. If the account already has a detector, import it instead
# of creating a second one (only one detector per region is allowed):
#   terraform import aws_guardduty_detector.main <detector-id>
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
