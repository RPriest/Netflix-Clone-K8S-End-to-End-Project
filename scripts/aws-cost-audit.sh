#!/usr/bin/env bash
#
# ============================================================================
# AWS BILLING AUDIT - finds resources still running/present that could be
# accruing charges. Read-only: it never deletes or modifies anything.
#
# Focused on us-east-1 (where the Phase 2 doc built everything), but also
# does a lightweight all-region sweep for the classic "silent cost" items
# that don't always get cleaned up by tag-based teardown: EBS volumes,
# Elastic IPs, NAT Gateways, and Load Balancers.
#
# Usage: ./aws-cost-audit.sh
# ============================================================================
set -uo pipefail
REGION="us-east-1"
echo "Account: $(aws sts get-caller-identity --query Account --output text)"
echo "Primary region checked: $REGION  (plus an all-region sweep below)"
echo "============================================================"
section() { echo -e "\n--- $1 ---"; }
# ---- Always-billing / easy-to-forget items in the primary region ----------
section "EKS clusters"
aws eks list-clusters --region "$REGION" --output table
section "EC2 instances (running or stopped - stopped still bills for EBS)"
aws ec2 describe-instances --region "$REGION" \
  --query "Reservations[].Instances[].[InstanceId,InstanceType,State.Name,Tags[?Key=='Name'].Value|[0]]" \
  --output table
section "EBS volumes (bills even when unattached)"
aws ec2 describe-volumes --region "$REGION" \
  --query "Volumes[].[VolumeId,Size,State,VolumeType]" --output table
section "Elastic IPs (bills ~\$3.6/mo each if NOT attached to a running instance)"
aws ec2 describe-addresses --region "$REGION" \
  --query "Addresses[].[PublicIp,InstanceId,AssociationId,NetworkInterfaceId]" --output table
section "NAT Gateways (~\$32/mo each - eksctl creates one per AZ by default)"
aws ec2 describe-nat-gateways --region "$REGION" --filter "Name=state,Values=available,pending" \
  --query "NatGateways[].[NatGatewayId,State,VpcId]" --output table
section "Load Balancers (ALB/NLB - usually created by k8s Ingress/Service, not by you directly)"
aws elbv2 describe-load-balancers --region "$REGION" \
  --query "LoadBalancers[].[LoadBalancerName,Type,State.Code,VpcId]" --output table 2>/dev/null
aws elb describe-load-balancers --region "$REGION" \
  --query "LoadBalancerDescriptions[].[LoadBalancerName,VPCId]" --output table 2>/dev/null
section "ECR repositories (storage cost per GB)"
aws ecr describe-repositories --region "$REGION" \
  --query "repositories[].[repositoryName,repositoryUri]" --output table
section "Secrets Manager secrets (~\$0.40/mo each)"
aws secretsmanager list-secrets --region "$REGION" \
  --query "SecretList[].[Name,DeletedDate]" --output table
section "CloudTrail trails (storage + possible data-event cost)"
aws cloudtrail list-trails --region "$REGION" --output table
section "KMS customer-managed keys (bills ~\$1/mo EACH even while PendingDeletion)"
aws kms list-aliases --region "$REGION" \
  --query "Aliases[?starts_with(AliasName, 'alias/netflix-devsecops') || starts_with(AliasName, 'alias/ssm-session')].[AliasName,TargetKeyId]" \
  --output table
for ALIAS in alias/netflix-devsecops-app-key alias/ssm-session-key; do
  KEY_ID=$(aws kms describe-key --key-id "$ALIAS" --region "$REGION" --query 'KeyMetadata.KeyId' --output text 2>/dev/null)
  if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
    STATE=$(aws kms describe-key --key-id "$KEY_ID" --region "$REGION" --query 'KeyMetadata.KeyState' --output text 2>/dev/null)
    DELETE_DATE=$(aws kms describe-key --key-id "$KEY_ID" --region "$REGION" --query 'KeyMetadata.DeletionDate' --output text 2>/dev/null)
    echo "  $ALIAS ($KEY_ID) -> state: $STATE  $( [[ "$STATE" == "PendingDeletion" ]] && echo "(still billing until $DELETE_DATE)" )"
  else
    echo "  $ALIAS -> not found (already fully deleted)."
  fi
done
section "GuardDuty detectors (cost scales with data volume analyzed)"
GD_RAW=$(aws guardduty list-detectors --region "$REGION" --output table 2>&1)
if echo "$GD_RAW" | grep -q "SubscriptionRequiredException"; then
  echo "  Can't check via API: this account/access key isn't entitled to call GuardDuty"
  echo "  (SubscriptionRequiredException). This is NOT the same as 'no detector' - verify"
  echo "  directly in the Console (Services -> GuardDuty) if this account might have one enabled."
else
  echo "$GD_RAW"
fi
section "S3 buckets containing 'devsecops' or 'netflix'"
aws s3 ls | grep -iE "devsecops|netflix" || echo "None found."
section "VPC peering connections (active or pending)"
aws ec2 describe-vpc-peering-connections --region "$REGION" \
  --query "VpcPeeringConnections[?Status.Code=='active' || Status.Code=='pending-acceptance'].[VpcPeeringConnectionId,Status.Code,RequesterVpcInfo.VpcId,AccepterVpcInfo.VpcId]" \
  --output table
section "Non-default VPCs (leftover eksctl VPC = subnets + NAT + IGW all billing)"
aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=false \
  --query "Vpcs[].[VpcId,CidrBlock,Tags[?Key=='Name'].Value|[0]]" --output table
section "Internet Gateways attached to non-default VPCs (no direct cost, but signals a leftover VPC)"
aws ec2 describe-internet-gateways --region "$REGION" \
  --query "InternetGateways[?Attachments[?State=='available']].[InternetGatewayId,Attachments[0].VpcId]" \
  --output table
# ---- Quick all-region sweep for the 4 classic silent-cost items -----------
section "ALL-REGION sweep: EC2 / EBS / EIP / NAT (in case anything was built outside us-east-1)"
for R in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  EC2_COUNT=$(aws ec2 describe-instances --region "$R" --filters Name=instance-state-name,Values=running,stopped \
    --query "length(Reservations[].Instances[])" --output text 2>/dev/null)
  EBS_COUNT=$(aws ec2 describe-volumes --region "$R" --query "length(Volumes[])" --output text 2>/dev/null)
  EIP_COUNT=$(aws ec2 describe-addresses --region "$R" --query "length(Addresses[])" --output text 2>/dev/null)
  NAT_COUNT=$(aws ec2 describe-nat-gateways --region "$R" --filter Name=state,Values=available,pending \
    --query "length(NatGateways[])" --output text 2>/dev/null)
  if [[ "$EC2_COUNT" != "0" || "$EBS_COUNT" != "0" || "$EIP_COUNT" != "0" || "$NAT_COUNT" != "0" ]]; then
    echo "  $R -> instances:$EC2_COUNT  volumes:$EBS_COUNT  eips:$EIP_COUNT  nat-gateways:$NAT_COUNT"
  fi
done
echo -e "\n============================================================"
echo "Review the tables above. Anything listed is either running now or"
echo "sitting there billing (EBS, EIP, NAT, secrets, S3 all bill at rest)."
echo "For a broader picture over time, also check:"
echo "  Console -> Billing -> Cost Explorer -> group by Service, last 7-30 days"
echo "  Console -> Resource Groups & Tag Editor -> search all regions, Project=DevSecOps"
echo "============================================================"
# ============================================================================

# ============================================================================
