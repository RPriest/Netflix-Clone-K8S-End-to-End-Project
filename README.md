# 🎬 Netflix Clone — End-to-End DevSecOps Kubernetes Project

A from-scratch DevSecOps build: bare AWS account → security-hardened
foundation → fully automated, security-gated CI/CD pipeline deploying a
real (deliberately imperfect) Netflix-clone frontend to Kubernetes. Four
phases, each documented end to end — not just the commands, but the
reasoning behind every decision.

## Why this project

Most "DevOps pipeline" tutorials wire tools together and stop. This one
treats security as a first-class requirement at every stage:
least-privilege IAM from the first command, no long-lived credentials
anywhere (OIDC for CI/CD, Secrets Manager for runtime secrets, IMDSv2
forced on every node), and 8+ independent scanners (SAST ×2, secrets,
SCA ×2, container, DAST, SBOM) feeding one centralized vulnerability
dashboard instead of scattered log output.

## Results so far

- 199 SAST findings triaged across two independent scanners
- 16 DAST alerts caught against the live deployment
- 100 known CVEs surfaced across 34 dependencies via SBOM + osv-scanner
- OpenSSF Scorecard improved 2.6 → 2.8
- A critical RCE-vulnerable dependency blocked from merging via PR gate
- Zero long-lived AWS credentials anywhere in CI/CD (OIDC end to end)

## Repo layout

```
Netflix-Clone-K8S-End-to-End-Project/
├── Application-Code/       ← the Netflix-clone frontend (the app being secured & deployed)
├── Jenkins/
│   └── Jenkinsfile         ← the full pipeline, 20+ stages
├── Dockerfile               ← multi-stage build
├── eks-cluster.yaml         ← eksctl cluster config
├── k8s-manifests/           ← Deployment, Service, Ingress, NetworkPolicy
├── monitoring/              ← Prometheus + Grafana + Alertmanager stack
├── policies/                ← IAM/KMS policy documents (ALB controller, Secrets Manager, CloudTrail, etc.)
├── scripts/                 ← teardown-phase2.sh, aws-cost-audit.sh
├── security-configs/        ← Gitleaks config
├── cosign.pub                ← image-signing public key (private key is a Jenkins credential, never committed)
├── upload-to-defectdojo.py
└── docs/                    ← write-ups, screenshots, phase-specific reference files
    ├── phase-1-aws-account-security/
    ├── phase-2-cicd-pipeline/
    ├── phase-3-terraform-automation/   (coming soon)
    └── phase-4/                         (coming soon)
```

**Rule of thumb:** if a file is something Jenkins, Docker, kubectl, or
eksctl actually reads at runtime, it lives at the repo root in its real
functional path. `docs/` is the narrative + evidence layer — write-ups
and screenshots — and links back to the real files rather than
duplicating them.

## Phases

| Phase | What it covers | Docs | Write-up |
|---|---|---|---|
| 1 | AWS account security — billing alarms, root lockdown, IAM, OIDC, VPC hardening, SSM over SSH | [docs/phase-1](./docs/phase-1-aws-account-security) | [Medium →](https://rpriest0.medium.com/%EF%B8%8F-end-to-end-devsecops-kubernetes-project-phase-1-of-4-7b870ce22666) |
| 2 | Full CI/CD pipeline — EKS, ECR, Jenkins, 8+ scanners, ArgoCD GitOps, DefectDojo, Prometheus/Grafana | [docs/phase-2](./docs/phase-2-cicd-pipeline) | [Medium →](https://rpriest0.medium.com/end-to-end-devsecops-kubernetes-project-phase-2-of-4-07d6b4da0ed6) |
| 3 | Terraform automation — infrastructure as code | 🚧 in progress | — |
| 4 | TBD | 🚧 coming soon | — |

## Stack

`AWS` `EKS` `ECR` `Terraform` `Jenkins` `ArgoCD` `Kubernetes`
`Gitleaks` `Semgrep` `NJSScan` `Trivy` `OWASP Dependency-Check` `RetireJS`
`ZAP` `CycloneDX SBOM` `osv-scanner` `DefectDojo` `Prometheus` `Grafana`
`OpenSSF Scorecard` `OIDC` `AWS Secrets Manager` `SSM`

## Author

Samuel Bamgbose — DevSecOps Engineer | Penetration Tester
[Portfolio](https://rpriest.github.io) ·
[GitHub](https://github.com/RPriest)
