#!/usr/bin/env bash
#
# ============================================================================
# TEARDOWN - Phase 2: Netflix Clone DevSecOps Pipeline (Complete Standalone)
# ============================================================================
# Reverses everything provisioned in the Phase 2 document:
#   EKS cluster + nodegroups, ALB Controller, ECR, 3x EC2 servers,
#   security groups, VPC peering, ArgoCD, Prometheus/Grafana (Helm),
#   Secrets Manager secret, GuardDuty detector, CloudTrail trail + S3 bucket,
#   the Monitoring-Role / DefectDojo-Role IAM roles and instance profiles
#   from Module 2.4, every inline policy Phase 2 added to EC2-SSM-Role, the
#   two customer-managed KMS keys created in Modules 2.2 and 2.4, the Phase 1
#   VPC Flow Log, and its destination S3 bucket.
#
# It does NOT touch Phase 1 resources that Phase 2 only *referenced*:
#   EC2-SSM-Role / EC2-SSM-Profile itself (the role stays, just stripped of
#   the policies this project added to it), and the SSM-SessionManagerRunShell
#   document (Phase 2 only edited it).
#
# It DOES remove the VPC Flow Log, its destination S3 bucket
# (devsecops-vpc-flow-logs-<account-id>), and the SSM session-recording KMS
# key — full cleanup, nothing left billing. Phase 3 creates its own flow-log
# bucket as a real Terraform resource rather than depending on this one, so
# there's no cross-phase dependency left to worry about here.
#
# Usage:
#   chmod +x teardown-phase2.sh
#   ./teardown-phase2.sh            # interactive, asks before each stage
#   ./teardown-phase2.sh --yes      # no prompts, just go
# ============================================================================
set -uo pipefail
REGION="us-east-1"
CLUSTER_NAME="netflix-devsecops"
ECR_REPO="netflix-clone"
SECRET_NAME="netflix-clone/prod/cicd-secrets"
TRAIL_NAME="netflix-devsecops-trail"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")"
CT_BUCKET="netflix-devsecops-cloudtrail-logs-${ACCOUNT_ID}"
AUTO_YES=false
case "${1:-}" in
  --yes|-y|yes) AUTO_YES=true ;;
esac
confirm() {
  $AUTO_YES && return 0
  read -r -p "$1 [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}
step() { echo -e "\n========== $1 ==========\n"; }
if [[ -z "$ACCOUNT_ID" ]]; then
  echo "Could not resolve AWS account ID - is the AWS CLI configured (aws configure / SSO login)?"
  exit 1
fi
echo "Account: $ACCOUNT_ID   Region: $REGION   Cluster: $CLUSTER_NAME"
confirm "This will DELETE the Phase 2 infrastructure above. Continue?" || { echo "Aborted."; exit 0; }
# ----------------------------------------------------------------------------
# 1. Kubernetes-level cleanup FIRST - anything that provisioned an AWS ALB/NLB
#    (Ingress, ArgoCD, monitoring services) must be deleted WHILE the ALB
#    controller is still running, and we must WAIT for the real AWS load
#    balancer to disappear before touching the controller. Uninstalling the
#    controller before the ALB it owns finishes deprovisioning orphans the
#    ALB, which then blocks `eksctl delete cluster` and every stack that
#    depends on its ENIs.
# ----------------------------------------------------------------------------
step "1/15 - Kubernetes: ArgoCD, Ingress, monitoring stack"
if kubectl cluster-info >/dev/null 2>&1; then
  echo "Deleting Ingress objects (releases any ALBs the controller created)..."
  kubectl delete ingress --all --all-namespaces --ignore-not-found=true --wait=true --timeout=120s
  echo "Waiting for the AWS load balancer(s) created by that Ingress to actually disappear..."
  ALB_WAIT_SECS=0
  ALB_WAIT_MAX=600   # 10 minutes
  while true; do
    LB_COUNT=$(aws elbv2 describe-load-balancers --region "$REGION" \
      --query "length(LoadBalancers[?starts_with(LoadBalancerName, 'k8s-')])" \
      --output text 2>/dev/null || echo "0")
    [[ "$LB_COUNT" == "0" || "$LB_COUNT" == "None" ]] && break
    if (( ALB_WAIT_SECS >= ALB_WAIT_MAX )); then
      echo "  WARNING: $LB_COUNT k8s-managed load balancer(s) still present after ${ALB_WAIT_MAX}s."
      echo "  Listing them so you can delete manually if the controller can't finish:"
      aws elbv2 describe-load-balancers --region "$REGION" \
        --query "LoadBalancers[?starts_with(LoadBalancerName, 'k8s-')].[LoadBalancerName,LoadBalancerArn,State.Code]" \
        --output table
      confirm "Force-delete these load balancer(s) directly via the ELBv2 API now?" && {
        for ARN in $(aws elbv2 describe-load-balancers --region "$REGION" \
          --query "LoadBalancers[?starts_with(LoadBalancerName, 'k8s-')].LoadBalancerArn" --output text); do
          echo "  Deleting $ARN"
          aws elbv2 delete-load-balancer --load-balancer-arn "$ARN" --region "$REGION" || true
        done
        sleep 20
      }
      break
    fi
    echo "  Still $LB_COUNT load balancer(s) pending deletion - waiting 15s (${ALB_WAIT_SECS}s elapsed)..."
    sleep 15
    ALB_WAIT_SECS=$((ALB_WAIT_SECS + 15))
  done
  echo "Deleting ArgoCD (this also releases the internal load balancer fronting argocd-server)..."
  kubectl delete namespace argocd --ignore-not-found=true --wait=true --timeout=180s
  echo "Uninstalling monitoring Helm releases..."
  helm uninstall k8s-node-exporter -n monitoring 2>/dev/null || true
  helm uninstall kube-state-metrics -n monitoring 2>/dev/null || true
  kubectl delete namespace monitoring --ignore-not-found=true
  echo "Re-checking for any load balancer still lingering (ArgoCD's, or a slow finalizer)..."
  aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[?starts_with(LoadBalancerName, 'k8s-') || contains(LoadBalancerName, 'argocd')].[LoadBalancerName,LoadBalancerArn,State.Code]" \
    --output table 2>/dev/null
  echo "Uninstalling AWS Load Balancer Controller (ALBs confirmed gone above)..."
  helm uninstall aws-load-balancer-controller -n kube-system 2>/dev/null || true
else
  echo "kubectl not pointed at the cluster (or cluster already gone) - skipping k8s cleanup."
  echo "Checking directly for orphaned k8s-managed load balancers from a prior run..."
  aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[?starts_with(LoadBalancerName, 'k8s-') || contains(LoadBalancerName, 'argocd')].[LoadBalancerName,LoadBalancerArn,State.Code]" \
    --output table 2>/dev/null
fi
# ----------------------------------------------------------------------------
# 2. IAM service account created via eksctl for the ALB controller
# ----------------------------------------------------------------------------
step "2/15 - IAM service account: aws-load-balancer-controller"
eksctl delete iamserviceaccount \
  --cluster="$CLUSTER_NAME" \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --region "$REGION" 2>/dev/null || echo "  (already gone or cluster unreachable)"
echo "Deleting IAM policy AWSLoadBalancerControllerIAMPolicy..."
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/AWSLoadBalancerControllerIAMPolicy"
aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null || echo "  (not found - may still be attached; detach roles first if this fails)"
# ----------------------------------------------------------------------------
# 3. VPC peering (default VPC <-> EKS VPC) - must go before either VPC deletes
# ----------------------------------------------------------------------------
step "3/15 - VPC peering connection"
# NOTE: do NOT require a Name tag here - the peering connection this project
# creates often has none, and filtering on it silently skips a real, billing
# (well, free, but VPC-deletion-blocking) active connection.
PEER_IDS=$(aws ec2 describe-vpc-peering-connections \
  --filters "Name=status-code,Values=active,pending-acceptance" \
  --query "VpcPeeringConnections[].VpcPeeringConnectionId" \
  --output text --region "$REGION" 2>/dev/null)
if [[ -n "$PEER_IDS" && "$PEER_IDS" != "None" ]]; then
  for PEER_ID in $PEER_IDS; do
    echo "Deleting peering connection: $PEER_ID"
    aws ec2 delete-vpc-peering-connection --vpc-peering-connection-id "$PEER_ID" --region "$REGION" || true
    echo "  Checking every route table in the default VPC for now-blackholed routes pointing at $PEER_ID..."
    DEFAULT_VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
    if [[ -n "$DEFAULT_VPC_ID" && "$DEFAULT_VPC_ID" != "None" ]]; then
      # RouteTables[0] alone isn't enough - a subnet-specific route table
      # (e.g. the one associated with the Jenkins subnet) is not guaranteed
      # to be index 0, so every route table in the VPC needs checking.
      ALL_RTBS=$(aws ec2 describe-route-tables --region "$REGION" --filters "Name=vpc-id,Values=$DEFAULT_VPC_ID" --query 'RouteTables[].RouteTableId' --output text 2>/dev/null)
      for RTB in $ALL_RTBS; do
        STALE_CIDRS=$(aws ec2 describe-route-tables --region "$REGION" --route-table-ids "$RTB" \
          --query "RouteTables[0].Routes[?VpcPeeringConnectionId=='${PEER_ID}'].DestinationCidrBlock" --output text 2>/dev/null)
        for CIDR in $STALE_CIDRS; do
          echo "    Removing stale route $CIDR from $RTB"
          aws ec2 delete-route --route-table-id "$RTB" --destination-cidr-block "$CIDR" --region "$REGION" 2>/dev/null || true
        done
      done
    fi
  done
else
  echo "No active/pending peering connection found."
fi
# ----------------------------------------------------------------------------
# 4. Extra spot nodegroup, then the EKS cluster itself
#    (eksctl create cluster -f eks-cluster.yaml also owns the cluster's own
#     VPC/subnets/NAT gateway - eksctl delete cluster tears all of that down,
#     but ONLY if nothing is still holding an ENI open in that VPC - hence
#     stage 1's ALB wait-loop above.)
# ----------------------------------------------------------------------------
step "4/15 - EKS nodegroups + cluster ($CLUSTER_NAME)"
eksctl delete nodegroup --cluster "$CLUSTER_NAME" --name netflix-workers-spot --region "$REGION" 2>/dev/null || true
if confirm "Delete the EKS cluster '$CLUSTER_NAME' now? (15-20 min, this is the big one)"; then
  CLUSTER_DELETE_OK=false
  CLUSTER_ALREADY_GONE=false
  for attempt in 1 2; do
    echo "  Attempt $attempt/2..."
    ERR_OUT=$(eksctl delete cluster --name "$CLUSTER_NAME" --region "$REGION" --wait 2>&1)
    if [[ $? -eq 0 ]]; then
      CLUSTER_DELETE_OK=true
      break
    fi
    echo "$ERR_OUT"
    if echo "$ERR_OUT" | grep -q "No cluster found for name"; then
      # The control plane already finished deleting in the background from an
      # earlier attempt (this is async on AWS's side), but the CloudFormation
      # stacks it owns - including the one holding the VPC/NAT Gateway/IGW -
      # never got torn down because that earlier run aborted partway through.
      # eksctl can't help anymore since it needs the cluster to exist to find
      # its stacks, so fall back to deleting them directly.
      CLUSTER_ALREADY_GONE=true
      break
    fi
    echo "  Cluster deletion failed on attempt $attempt. Checking for lingering ENIs from the ALB..."
    aws elbv2 describe-load-balancers --region "$REGION" \
      --query "LoadBalancers[?starts_with(LoadBalancerName, 'k8s-')].LoadBalancerArn" --output text 2>/dev/null \
      | tr '\t' '\n' | while read -r ARN; do
          [[ -z "$ARN" ]] && continue
          echo "    Found leftover LB $ARN - deleting it directly."
          aws elbv2 delete-load-balancer --load-balancer-arn "$ARN" --region "$REGION" || true
        done
    sleep 30
  done
  if $CLUSTER_ALREADY_GONE; then
    echo "  Control plane already gone. Falling back to direct CloudFormation stack cleanup for '$CLUSTER_NAME'..."
    STACKS=$(aws cloudformation list-stacks --region "$REGION" \
      --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE ROLLBACK_COMPLETE UPDATE_ROLLBACK_COMPLETE DELETE_FAILED \
      --query "StackSummaries[?starts_with(StackName, 'eksctl-${CLUSTER_NAME}-')].StackName" \
      --output text --region "$REGION" 2>/dev/null)
    if [[ -n "$STACKS" ]]; then
      echo "  Found stacks: $STACKS"
      # Delete nodegroup/addon/accessentry stacks first, the VPC-owning
      # "-cluster" stack last (it has dependents).
      NON_CLUSTER_STACKS=$(echo "$STACKS" | tr '\t' '\n' | grep -v -- "-cluster$" || true)
      CLUSTER_STACK=$(echo "$STACKS" | tr '\t' '\n' | grep -- "-cluster$" || true)
      # Polls a stack's status every 20s (printing it, so this doesn't look
      # hung) up to ~20 minutes. Returns 0 if it reaches DELETE_COMPLETE
      # (i.e. the stack is gone), 1 otherwise.
      wait_for_stack_delete() {
        local stack="$1"
        local elapsed=0
        local max=1200
        while true; do
          local status
          status=$(aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" \
            --query "Stacks[0].StackStatus" --output text 2>/dev/null)
          if [[ -z "$status" || "$status" == "None" ]]; then
            echo "      $stack -> gone (deleted)"
            return 0
          fi
          if [[ "$status" == "DELETE_FAILED" ]]; then
            echo "      $stack -> DELETE_FAILED. Reason(s):"
            aws cloudformation describe-stack-events --stack-name "$stack" --region "$REGION" \
              --query "StackEvents[?ResourceStatus=='DELETE_FAILED'].[LogicalResourceId,ResourceStatusReason]" \
              --output table 2>/dev/null
            return 1
          fi
          echo "      $stack -> $status  (${elapsed}s elapsed, still going - NAT Gateway teardown alone often takes several minutes)"
          if (( elapsed >= max )); then
            echo "      Giving up watching after ${max}s - check the CloudFormation console, it may still be progressing."
            return 1
          fi
          sleep 20
          elapsed=$((elapsed + 20))
        done
      }
      # Looks up the physical VPC ID owned by a given CFN stack (used to
      # scope the security-group cleanup below to just that VPC).
      find_stack_vpc_id() {
        local stack="$1"
        aws cloudformation describe-stack-resources --stack-name "$stack" --region "$REGION" \
          --query "StackResources[?ResourceType=='AWS::EC2::VPC'].PhysicalResourceId" \
          --output text 2>/dev/null
      }
      # EKS creates eks-cluster-sg-* (cluster SG) and, once the ALB
      # controller/VPC CNI are up, k8s-traffic-*/k8s-default-* SGs - all
      # OUTSIDE the eksctl CloudFormation template. delete-stack has no idea
      # they exist, so they're left behind referencing each other (cluster SG
      # <-> node SG rules for control-plane/kubelet traffic) and block the
      # VPC delete with "has dependencies and cannot be deleted." Revoke their
      # cross-referencing rules first, then delete them, before the stack
      # delete is even attempted.
      cleanup_eks_orphan_security_groups() {
        local vpc_id="$1"
        [[ -z "$vpc_id" || "$vpc_id" == "None" ]] && return 0
        echo "    Checking for EKS-auto-created security groups in $vpc_id (these live outside the CFN stack and block VPC deletion)..."
        local SG_IDS
        SG_IDS=$(aws ec2 describe-security-groups --region "$REGION" \
          --filters "Name=vpc-id,Values=$vpc_id" \
          --query "SecurityGroups[?starts_with(GroupName, \`eks-cluster-sg-\`) || starts_with(GroupName, \`k8s-traffic-\`) || starts_with(GroupName, \`k8s-default-\`)].GroupId" \
          --output text 2>/dev/null)
        if [[ -z "$SG_IDS" || "$SG_IDS" == "None" ]]; then
          echo "      None found."
          return 0
        fi
        echo "      Found: $SG_IDS"
        echo "      Revoking cross-referencing ingress/egress rules first..."
        for ID in $SG_IDS; do
          local INGRESS_JSON EGRESS_JSON
          INGRESS_JSON=$(aws ec2 describe-security-groups --group-ids "$ID" --region "$REGION" \
            --query "SecurityGroups[0].IpPermissions" --output json 2>/dev/null)
          if [[ -n "$INGRESS_JSON" && "$INGRESS_JSON" != "null" && "$INGRESS_JSON" != "[]" ]]; then
            aws ec2 revoke-security-group-ingress --group-id "$ID" --region "$REGION" \
              --ip-permissions "$INGRESS_JSON" 2>/dev/null || true
          fi
          EGRESS_JSON=$(aws ec2 describe-security-groups --group-ids "$ID" --region "$REGION" \
            --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>/dev/null)
          if [[ -n "$EGRESS_JSON" && "$EGRESS_JSON" != "null" && "$EGRESS_JSON" != "[]" ]]; then
            aws ec2 revoke-security-group-egress --group-id "$ID" --region "$REGION" \
              --ip-permissions "$EGRESS_JSON" 2>/dev/null || true
          fi
        done
        for ID in $SG_IDS; do
          local DELETED=false
          for attempt in 1 2 3; do
            echo "      Deleting $ID (attempt $attempt/3)..."
            if aws ec2 delete-security-group --group-id "$ID" --region "$REGION" 2>/dev/null; then
              DELETED=true
              break
            fi
            sleep 10
          done
          $DELETED || echo "      $ID still couldn't be deleted - check for a lingering ENI or another SG still referencing it."
        done
      }
      for S in $NON_CLUSTER_STACKS; do
        echo "    Deleting stack $S ..."
        aws cloudformation update-termination-protection --stack-name "$S" --no-enable-termination-protection --region "$REGION" >/dev/null || true
        aws cloudformation delete-stack --stack-name "$S" --region "$REGION"
        wait_for_stack_delete "$S" || echo "      (needs manual attention - check the CloudFormation console)"
      done
      if [[ -n "$CLUSTER_STACK" ]]; then
        STACK_VPC_ID=$(find_stack_vpc_id "$CLUSTER_STACK")
        cleanup_eks_orphan_security_groups "$STACK_VPC_ID"
        echo "    Deleting VPC/control-plane stack $CLUSTER_STACK (owns the NAT Gateway/IGW/subnets)..."
        aws cloudformation update-termination-protection --stack-name "$CLUSTER_STACK" --no-enable-termination-protection --region "$REGION" >/dev/null || true
        aws cloudformation delete-stack --stack-name "$CLUSTER_STACK" --region "$REGION"
        if wait_for_stack_delete "$CLUSTER_STACK"; then
          CLUSTER_DELETE_OK=true
        else
          echo "      Stack delete still failed after clearing the eks-cluster-sg-*/k8s-* groups - recheck for leftover ENIs or another blocking resource in the DELETE_FAILED reason above, then re-run:"
          echo "        cleanup_eks_orphan_security_groups $STACK_VPC_ID   # (rerun this script; it's idempotent)"
          echo "        aws cloudformation delete-stack --stack-name $CLUSTER_STACK --region $REGION"
        fi
      fi
    else
      echo "  No leftover eksctl-${CLUSTER_NAME}-* CloudFormation stacks found - VPC/NAT/IGW may already be gone, or were created outside CloudFormation."
      CLUSTER_DELETE_OK=true
    fi
  fi
  $CLUSTER_DELETE_OK || echo "  Cluster/VPC deletion still incomplete. Re-run this script, or clean up the remaining eksctl-${CLUSTER_NAME}-* CloudFormation stack(s) manually via the console."
  if $CLUSTER_DELETE_OK; then
    echo "  Checking for a VPC shell left behind by a Retain deletion policy, even though the stack itself finished..."
    LEFTOVER_VPC=$(aws ec2 describe-vpcs --region "$REGION" \
      --filters "Name=tag:Name,Values=eksctl-${CLUSTER_NAME}-cluster/VPC" \
      --query "Vpcs[0].VpcId" --output text 2>/dev/null)
    if [[ -n "$LEFTOVER_VPC" && "$LEFTOVER_VPC" != "None" ]]; then
      echo "    Found $LEFTOVER_VPC still present. It's not billing anything on its own (bare VPCs/subnets/"
      echo "    route tables are free), but it's worth clearing out so it doesn't eat into your VPC quota."
      confirm "    Delete this leftover VPC and anything still inside it (subnets, non-main route tables, non-default SGs/NACLs)?" && {
        for SUB in $(aws ec2 describe-subnets --region "$REGION" --filters "Name=vpc-id,Values=$LEFTOVER_VPC" --query "Subnets[].SubnetId" --output text); do
          echo "      Deleting subnet $SUB"
          aws ec2 delete-subnet --subnet-id "$SUB" --region "$REGION" || true
        done
        for RT in $(aws ec2 describe-route-tables --region "$REGION" --filters "Name=vpc-id,Values=$LEFTOVER_VPC" \
          --query "RouteTables[?Associations[0].Main!=\`true\`].RouteTableId" --output text 2>/dev/null); do
          echo "      Deleting route table $RT"
          aws ec2 delete-route-table --route-table-id "$RT" --region "$REGION" || true
        done
        for SG in $(aws ec2 describe-security-groups --region "$REGION" --filters "Name=vpc-id,Values=$LEFTOVER_VPC" \
          --query "SecurityGroups[?GroupName!='default'].GroupId" --output text 2>/dev/null); do
          echo "      Deleting security group $SG"
          aws ec2 delete-security-group --group-id "$SG" --region "$REGION" || true
        done
        for NACL in $(aws ec2 describe-network-acls --region "$REGION" --filters "Name=vpc-id,Values=$LEFTOVER_VPC" \
          --query "NetworkAcls[?IsDefault!=\`true\`].NetworkAclId" --output text 2>/dev/null); do
          echo "      Deleting network ACL $NACL"
          aws ec2 delete-network-acl --network-acl-id "$NACL" --region "$REGION" || true
        done
        echo "      Deleting VPC $LEFTOVER_VPC"
        aws ec2 delete-vpc --vpc-id "$LEFTOVER_VPC" --region "$REGION" || \
          echo "      Still couldn't delete - something else is still attached (check the console: leftover ENIs, VPC endpoints, or a Transit Gateway attachment)."
      }
    else
      echo "    None found - clean."
    fi
  fi
  if $CLUSTER_DELETE_OK; then
    echo "  Checking for any Elastic IPs left behind (should normally be released by the stack, but just in case)..."
    ORPHAN_EIPS=$(aws ec2 describe-addresses --region "$REGION" \
      --query "Addresses[?AssociationId==null].AllocationId" --output text 2>/dev/null)
    if [[ -n "$ORPHAN_EIPS" && "$ORPHAN_EIPS" != "None" ]]; then
      echo "    Found unassociated EIP(s): $ORPHAN_EIPS"
      confirm "  Release these unassociated Elastic IP(s)? (they bill ~\$3.6/mo each while idle)" && \
        for ALLOC in $ORPHAN_EIPS; do
          aws ec2 release-address --allocation-id "$ALLOC" --region "$REGION" || true
        done
    else
      echo "    None found."
    fi
  fi
else
  echo "  Skipped cluster deletion."
fi
# ----------------------------------------------------------------------------
# 5. EC2 instances (Jenkins, Monitoring, DefectDojo)
# ----------------------------------------------------------------------------
step "5/15 - EC2 instances"
INSTANCE_IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=DevSecOps" "Name=instance-state-name,Values=running,stopped" \
  --query "Reservations[].Instances[].InstanceId" --output text --region "$REGION")
if [[ -n "$INSTANCE_IDS" ]]; then
  echo "Terminating: $INSTANCE_IDS"
  aws ec2 terminate-instances --instance-ids $INSTANCE_IDS --region "$REGION"
  echo "Waiting for full termination (this blocks so security-group deletion below won't race it)..."
  aws ec2 wait instance-terminated --instance-ids $INSTANCE_IDS --region "$REGION"
else
  echo "No tagged (Project=DevSecOps) instances found."
fi
# ----------------------------------------------------------------------------
# 6. Security groups - the real blocker here isn't leftover ENIs, it's that
#    Jenkins-SG / Monitoring-SG / DefectDojo-SG reference EACH OTHER in their
#    own ingress/egress rules (e.g. Monitoring-SG allows traffic FROM
#    Jenkins-SG). AWS refuses to delete a group cited as a source/destination
#    in another group's rule, even with zero instances attached. Revoke all
#    cross-references first, THEN delete, with a couple of retries for any
#    trailing ENI detachment.
# ----------------------------------------------------------------------------
step "6/15 - Security groups: Jenkins-SG, Monitoring-SG, DefectDojo-SG"
declare -A SG_IDS
for SG in Jenkins-SG Monitoring-SG DefectDojo-SG; do
  SG_IDS[$SG]=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG" \
    --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null)
done
echo "Revoking any rules where these groups reference each other..."
for SG in "${!SG_IDS[@]}"; do
  ID="${SG_IDS[$SG]}"
  [[ -z "$ID" || "$ID" == "None" ]] && continue
  INGRESS_JSON=$(aws ec2 describe-security-groups --group-ids "$ID" --region "$REGION" \
    --query "SecurityGroups[0].IpPermissions" --output json 2>/dev/null)
  if [[ -n "$INGRESS_JSON" && "$INGRESS_JSON" != "null" && "$INGRESS_JSON" != "[]" ]]; then
    aws ec2 revoke-security-group-ingress --group-id "$ID" --region "$REGION" \
      --ip-permissions "$INGRESS_JSON" 2>/dev/null || true
  fi
  EGRESS_JSON=$(aws ec2 describe-security-groups --group-ids "$ID" --region "$REGION" \
    --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>/dev/null)
  if [[ -n "$EGRESS_JSON" && "$EGRESS_JSON" != "null" && "$EGRESS_JSON" != "[]" ]]; then
    aws ec2 revoke-security-group-egress --group-id "$ID" --region "$REGION" \
      --ip-permissions "$EGRESS_JSON" 2>/dev/null || true
  fi
done
for SG in Jenkins-SG Monitoring-SG DefectDojo-SG; do
  SG_ID="${SG_IDS[$SG]}"
  if [[ -n "$SG_ID" && "$SG_ID" != "None" ]]; then
    DELETED=false
    for attempt in 1 2 3; do
      echo "Deleting $SG ($SG_ID)... (attempt $attempt/3)"
      if aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION" 2>/dev/null; then
        DELETED=true
        break
      fi
      sleep 20
    done
    $DELETED || echo "  Still in use after 3 attempts - an ENI (e.g. from the NAT Gateway/ALB/VPC) may still be attached. Re-run this stage after the cluster/VPC is fully gone."
  else
    echo "$SG not found."
  fi
done
# ----------------------------------------------------------------------------
# 7. ECR repository
# ----------------------------------------------------------------------------
step "7/15 - ECR repository ($ECR_REPO)"
aws ecr delete-repository --repository-name "$ECR_REPO" --force --region "$REGION" 2>/dev/null || \
  echo "  Not found or already deleted."
# ----------------------------------------------------------------------------
# 8. Secrets Manager
# ----------------------------------------------------------------------------
step "8/15 - Secrets Manager ($SECRET_NAME)"
aws secretsmanager delete-secret --secret-id "$SECRET_NAME" \
  --force-delete-without-recovery --region "$REGION" 2>/dev/null || \
  echo "  Not found or already deleted."
# Drop --force-delete-without-recovery for a 7-30 day recovery window instead.
# ----------------------------------------------------------------------------
# 9. CloudTrail trail - stop logging and give the last in-flight deliveries
#    a moment to land before we try to empty the bucket in the next stage.
# ----------------------------------------------------------------------------
step "9/15 - CloudTrail trail ($TRAIL_NAME)"
aws cloudtrail stop-logging --name "$TRAIL_NAME" --region "$REGION" 2>/dev/null || true
aws cloudtrail delete-trail --name "$TRAIL_NAME" --region "$REGION" 2>/dev/null || \
  echo "  Not found or already deleted."
echo "Giving in-flight log deliveries a few seconds to land before emptying the bucket..."
sleep 30
# ----------------------------------------------------------------------------
# 10. CloudTrail S3 bucket - must be FULLY empty (including any versions/
#     delete markers) before it can be deleted. A single `s3 rm --recursive`
#     can lose a race against CloudTrail's tail-end deliveries, so retry the
#     empty-check in a loop before calling delete-bucket.
# ----------------------------------------------------------------------------
step "10/15 - S3 bucket ($CT_BUCKET)"
if aws s3api head-bucket --bucket "$CT_BUCKET" 2>/dev/null; then
  confirm "Empty + delete bucket $CT_BUCKET ? (irreversible - contains audit logs)" && {
    for attempt in 1 2 3 4 5; do
      aws s3 rm "s3://${CT_BUCKET}" --recursive >/dev/null
      # Also clear any object versions / delete markers (versioned buckets)
      VERSIONS_JSON=$(aws s3api list-object-versions --bucket "$CT_BUCKET" \
        --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
      if [[ -n "$VERSIONS_JSON" && "$VERSIONS_JSON" != '{"Objects": null}' ]]; then
        echo "$VERSIONS_JSON" | jq -e '.Objects | length > 0' >/dev/null 2>&1 && \
          aws s3api delete-objects --bucket "$CT_BUCKET" --delete "$VERSIONS_JSON" >/dev/null 2>&1 || true
      fi
      MARKERS_JSON=$(aws s3api list-object-versions --bucket "$CT_BUCKET" \
        --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
      if [[ -n "$MARKERS_JSON" && "$MARKERS_JSON" != '{"Objects": null}' ]]; then
        echo "$MARKERS_JSON" | jq -e '.Objects | length > 0' >/dev/null 2>&1 && \
          aws s3api delete-objects --bucket "$CT_BUCKET" --delete "$MARKERS_JSON" >/dev/null 2>&1 || true
      fi
      REMAINING=$(aws s3api list-objects-v2 --bucket "$CT_BUCKET" --query 'length(Contents[])' --output text 2>/dev/null)
      [[ "$REMAINING" == "0" || "$REMAINING" == "None" ]] && break
      echo "  $REMAINING object(s) still landing (CloudTrail tail-end delivery) - retrying in 15s (attempt $attempt/5)..."
      sleep 15
    done
    aws s3api delete-bucket --bucket "$CT_BUCKET" --region "$REGION" || \
      echo "  Bucket still not empty after retries - run 'aws s3 ls s3://${CT_BUCKET}' and delete the stragglers manually, then delete the bucket."
  }
else
  echo "  Bucket not found."
fi
# ----------------------------------------------------------------------------
# 11. GuardDuty detector - distinguish "no detector" from "this account isn't
#     entitled to call the API at all" (SubscriptionRequiredException), which
#     otherwise gets mislabeled as "no detector found."
# ----------------------------------------------------------------------------
step "11/15 - GuardDuty"
GD_ERR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region "$REGION" 2>&1 >/tmp/gd_out)
DETECTOR_ID=$(cat /tmp/gd_out 2>/dev/null)
if echo "$GD_ERR" | grep -q "SubscriptionRequiredException"; then
  echo "  Can't check GuardDuty via the API - this account/access key isn't entitled to the GuardDuty"
  echo "  service (SubscriptionRequiredException), not necessarily 'no detector.' Check the Console"
  echo "  directly (Services -> GuardDuty) if you need to confirm/disable it."
elif [[ -n "$DETECTOR_ID" && "$DETECTOR_ID" != "None" ]]; then
  echo "  Found detector: $DETECTOR_ID"
  echo "  NOTE: this may be an account-wide control shared with other work. Confirm before deleting."
  confirm "Delete GuardDuty detector $DETECTOR_ID ?" && \
    aws guardduty delete-detector --detector-id "$DETECTOR_ID" --region "$REGION"
else
  echo "  No detector found."
fi
# ----------------------------------------------------------------------------
# 12. IAM cleanup - everything Modules 2.4 and 2.18 attached or created.
#     EC2-SSM-Role itself is a Phase 1 resource and stays, but all FOUR
#     inline policies Phase 2 put on it come off: the three from Module 2.4
#     (CloudWatch Logs, SSM session KMS, S3 session logging) and the one from
#     Module 2.18 (Secrets Manager + app-key decrypt - leaving this attached
#     after the secret and key are gone is exactly the kind of stale grant
#     this cleanup exists to avoid). Monitoring-Role and DefectDojo-Role,
#     including their instance profiles, are Phase 2's own roles and get
#     deleted outright rather than left behind.
# ----------------------------------------------------------------------------
step "12/15 - IAM: EC2-SSM-Role policies, Monitoring-Role, DefectDojo-Role"
echo "Removing the inline policies Phase 2 added to EC2-SSM-Role..."
for POLICY in SSM-CloudWatchLogs-DescribeLogGroups SSM-KMS-SessionEncryption SSM-S3Logging-Access SecretsManagerAccess; do
  aws iam delete-role-policy --role-name EC2-SSM-Role --policy-name "$POLICY" 2>/dev/null && \
    echo "  Removed $POLICY from EC2-SSM-Role." || \
    echo "  $POLICY not found on EC2-SSM-Role, already removed, or the role doesn't exist here."
done
echo "Removing Monitoring-Role and DefectDojo-Role, and their instance profiles..."
for ROLE in Monitoring-Role DefectDojo-Role; do
  PROFILE="${ROLE}-Profile"
  if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
    for POLICY in SSM-CloudWatchLogs-DescribeLogGroups SSM-KMS-SessionEncryption SSM-S3Logging-Access; do
      aws iam delete-role-policy --role-name "$ROLE" --policy-name "$POLICY" 2>/dev/null || true
    done
    aws iam detach-role-policy --role-name "$ROLE" \
      --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true
    if aws iam get-instance-profile --instance-profile-name "$PROFILE" >/dev/null 2>&1; then
      aws iam remove-role-from-instance-profile --instance-profile-name "$PROFILE" --role-name "$ROLE" 2>/dev/null || true
      aws iam delete-instance-profile --instance-profile-name "$PROFILE" 2>/dev/null || true
    fi
    aws iam delete-role --role-name "$ROLE" 2>/dev/null && echo "  Deleted $ROLE." || \
      echo "  Couldn't delete $ROLE - check for leftover inline/attached policies."
  else
    echo "  $ROLE not found, already removed."
  fi
done
# ----------------------------------------------------------------------------
# 13. KMS keys - both customer-managed keys this project created (the app
#     key from Module 2.2 and the SSM session-recording key from Module 2.4).
#     Keys can't be deleted immediately; this schedules them for deletion
#     after a waiting period so nothing is lost if you change your mind.
# ----------------------------------------------------------------------------
step "13/15 - KMS keys: netflix-devsecops-app-key, ssm-session-key"
# The app-key was created via an alias (module 2.2 / Terraform), so the
# alias lookup finds it directly. But Phase 1's SSM session key was created
# with a bare `aws kms create-key` and no `create-alias` step ever followed,
# so `alias/ssm-session-key` matches nothing even though the key still
# exists. Fall back to matching on the key's Description instead of giving
# up when the alias lookup comes back empty.
find_kms_key_id() {
  local ALIAS="$1" DESC_SUBSTR="$2"
  local KEY_ID
  KEY_ID=$(aws kms describe-key --key-id "$ALIAS" --region "$REGION" --query 'KeyMetadata.KeyId' --output text 2>/dev/null)
  if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
    echo "$KEY_ID"
    return
  fi
  for K in $(aws kms list-keys --region "$REGION" --query "Keys[].KeyId" --output text 2>/dev/null); do
    D=$(aws kms describe-key --key-id "$K" --region "$REGION" --query 'KeyMetadata.Description' --output text 2>/dev/null)
    if [[ "$D" == *"$DESC_SUBSTR"* ]]; then
      echo "$K"
      return
    fi
  done
}
delete_kms_key() {
  local ALIAS="$1" DESC_SUBSTR="$2"
  local KEY_ID
  KEY_ID=$(find_kms_key_id "$ALIAS" "$DESC_SUBSTR")
  if [[ -n "$KEY_ID" && "$KEY_ID" != "None" ]]; then
    STATE=$(aws kms describe-key --key-id "$KEY_ID" --region "$REGION" --query 'KeyMetadata.KeyState' --output text 2>/dev/null)
    if [[ "$STATE" == "PendingDeletion" ]]; then
      echo "  $ALIAS ($KEY_ID) is already scheduled for deletion."
      return
    fi
    confirm "Schedule $ALIAS ($KEY_ID) for deletion in 7 days? (keeps a recovery window; nothing is billed for a key pending deletion)" && {
      aws kms delete-alias --alias-name "$ALIAS" --region "$REGION" 2>/dev/null || true
      aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 7 --region "$REGION" >/dev/null && \
        echo "  Scheduled $KEY_ID for deletion in 7 days." || \
        echo "  Couldn't schedule deletion - check the key's grants/state in the console."
    }
  else
    echo "  $ALIAS not found by alias or by description match (\"$DESC_SUBSTR\") - already deleted, or check the console directly."
  fi
}
delete_kms_key "alias/netflix-devsecops-app-key" "app"
delete_kms_key "alias/ssm-session-key" "SSM session"
# ----------------------------------------------------------------------------
# 14. VPC Flow Log (Phase 1) - not referenced anywhere until now. Deleting
#     the log here, before the bucket it writes to, avoids AWS silently
#     recreating log-delivery activity against a bucket that's mid-deletion.
# ----------------------------------------------------------------------------
step "14/15 - VPC Flow Log"
FLOW_LOG_IDS=$(aws ec2 describe-flow-logs --region "$REGION" \
  --filter "Name=tag:Project,Values=DevSecOps" \
  --query "FlowLogs[].FlowLogId" --output text 2>/dev/null)
if [[ -z "$FLOW_LOG_IDS" ]]; then
  # Fallback: not every flow log got the Project tag - match by the default
  # VPC directly, since that's the only place Phase 1 created one.
  DEFAULT_VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
    --filters Name=isDefault,Values=true --query "Vpcs[0].VpcId" --output text 2>/dev/null)
  if [[ -n "$DEFAULT_VPC_ID" && "$DEFAULT_VPC_ID" != "None" ]]; then
    FLOW_LOG_IDS=$(aws ec2 describe-flow-logs --region "$REGION" \
      --filter "Name=resource-id,Values=$DEFAULT_VPC_ID" \
      --query "FlowLogs[].FlowLogId" --output text 2>/dev/null)
  fi
fi
if [[ -n "$FLOW_LOG_IDS" && "$FLOW_LOG_IDS" != "None" ]]; then
  echo "  Found flow log(s): $FLOW_LOG_IDS"
  confirm "Delete these VPC Flow Log(s)?" && {
    aws ec2 delete-flow-logs --region "$REGION" --flow-log-ids $FLOW_LOG_IDS >/dev/null && \
      echo "  Deleted." || echo "  Couldn't delete - check manually with 'aws ec2 describe-flow-logs'."
  }
else
  echo "  No flow logs found (already deleted, or none were ever created)."
fi
# ----------------------------------------------------------------------------
# 15. VPC Flow Logs S3 bucket - Phase 3's vpc module creates its own bucket
#     as a real Terraform resource rather than depending on this one still
#     existing, so there's no cross-phase dependency left to protect here.
# ----------------------------------------------------------------------------
step "15/15 - S3 bucket: devsecops-vpc-flow-logs-${ACCOUNT_ID}"
FLOW_BUCKET="devsecops-vpc-flow-logs-${ACCOUNT_ID}"
if aws s3api head-bucket --bucket "$FLOW_BUCKET" 2>/dev/null; then
  confirm "Empty and delete S3 bucket $FLOW_BUCKET?" && {
    echo "  Emptying $FLOW_BUCKET (including all object versions, since versioning may be enabled)..."
    aws s3 rm "s3://${FLOW_BUCKET}" --recursive >/dev/null 2>&1 || true
    for attempt in 1 2 3 4 5; do
      VERSIONS_JSON=$(aws s3api list-object-versions --bucket "$FLOW_BUCKET" \
        --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
      if [[ -n "$VERSIONS_JSON" && "$VERSIONS_JSON" != '{"Objects": null}' ]]; then
        echo "$VERSIONS_JSON" | jq -e '.Objects | length > 0' >/dev/null 2>&1 && \
          aws s3api delete-objects --bucket "$FLOW_BUCKET" --delete "$VERSIONS_JSON" >/dev/null 2>&1 || true
      fi
      MARKERS_JSON=$(aws s3api list-object-versions --bucket "$FLOW_BUCKET" \
        --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null)
      if [[ -n "$MARKERS_JSON" && "$MARKERS_JSON" != '{"Objects": null}' ]]; then
        echo "$MARKERS_JSON" | jq -e '.Objects | length > 0' >/dev/null 2>&1 && \
          aws s3api delete-objects --bucket "$FLOW_BUCKET" --delete "$MARKERS_JSON" >/dev/null 2>&1 || true
      fi
      REMAINING=$(aws s3api list-objects-v2 --bucket "$FLOW_BUCKET" --query 'length(Contents[])' --output text 2>/dev/null)
      [[ "$REMAINING" == "0" || "$REMAINING" == "None" ]] && break
      echo "  $REMAINING object(s) still present - retrying in 15s (attempt $attempt/5)..."
      sleep 15
    done
    aws s3api delete-bucket --bucket "$FLOW_BUCKET" --region "$REGION" && \
      echo "  Deleted $FLOW_BUCKET." || \
      echo "  Bucket still not empty after retries - run 'aws s3 ls s3://${FLOW_BUCKET}' and delete the stragglers manually, then delete the bucket."
  }
else
  echo "  Bucket not found."
fi
# ----------------------------------------------------------------------------
# Local cleanup
# ----------------------------------------------------------------------------
step "Local kubeconfig"
kubectl config delete-context "$(kubectl config current-context 2>/dev/null)" 2>/dev/null || true
sed -i.bak "/${CLUSTER_NAME}/d" ~/.kube/config 2>/dev/null || true
echo -e "\nDone. Run the verification commands below (or aws-cost-audit.sh) to confirm everything is gone."
echo "----------------------------------------------------------------------"
echo "aws eks list-clusters --region $REGION"
echo "aws ec2 describe-instances --filters Name=tag:Project,Values=DevSecOps --region $REGION"
echo "aws ecr describe-repositories --region $REGION"
echo "aws secretsmanager list-secrets --region $REGION"
echo "aws cloudtrail list-trails --region $REGION"
echo "aws s3 ls | grep netflix-devsecops"
echo "aws ec2 describe-nat-gateways --region $REGION --filter Name=state,Values=available,pending"
echo "aws ec2 describe-vpcs --region $REGION --filters Name=isDefault,Values=false"
echo "aws iam list-roles --query \"Roles[?RoleName=='Monitoring-Role' || RoleName=='DefectDojo-Role']\""
echo "aws kms list-aliases --query \"Aliases[?AliasName=='alias/netflix-devsecops-app-key' || AliasName=='alias/ssm-session-key']\""
echo "aws ec2 describe-flow-logs --region $REGION"
echo "aws s3 ls | grep devsecops-vpc-flow-logs"
echo "----------------------------------------------------------------------"
