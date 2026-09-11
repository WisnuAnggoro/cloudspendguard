# CloudSpendGuard: Related Work

A landscape scan of tools that overlap with CloudSpendGuard's problem space (unified cloud cost and security posture management). The purpose of this document is to (a) acknowledge existing work honestly, (b) identify the specific gap CloudSpendGuard fills, and (c) provide citations for the Unit 2 problem statement and Unit 3 detailed design.

Last updated: 2026-09-06

## Executive summary

Several tools address parts of the FinOps + Cloud Security Posture Management (CSPM) problem, but no existing open-source tool combines the three characteristics that define CloudSpendGuard: (1) a **local-first, developer-workstation CLI**, (2) an **explicit, tunable joint cost × risk × blast-radius prioritization function**, and (3) an **LLM-assisted remediation module with a generate-then-verify safety loop**. The closest commercial parallels ([Wiz Cloud Cost](https://www.wiz.io/solutions/cloud-cost), [Orca Security Cost Optimization](https://orca.security/resources/press-releases/orca-launches-new-cloud-cost-optimization-capabilities/)) are closed-source SaaS platforms priced for enterprise buyers. The closest open-source parallel ([Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian)) is a rule-execution engine rather than a scoring-and-prioritization tool.

## Category 1: Commercial CNAPP platforms with cost modules (closest overlap)

| Tool | Vendor | Strengths | Gaps vs. CloudSpendGuard |
|---|---|---|---|
| [Wiz Cloud Cost](https://www.wiz.io/solutions/cloud-cost) | Wiz | Mature CSPM engine; context-aware cost recommendations; graph-based reasoning ([Wiz blog, 2024](https://www.wiz.io/blog/introducing-wiz-cloud-cost)) | Closed source; SaaS-only (agentless data collection off-prem); enterprise pricing (typically over USD 50K/year); browser-first UI, no CLI-native workflow |
| [Orca Cost Optimization](https://orca.security/resources/press-releases/orca-launches-new-cloud-cost-optimization-capabilities/) | Orca Security | SideScanning technology; combined CSPM + cost view; multi-cloud | Closed source; SaaS-only; enterprise pricing |
| [Microsoft Defender for Cloud CSPM](https://www.microsoft.com/en-us/security/business/cloud-security/microsoft-defender-cloud-security-posture-management) | Microsoft | Deep Azure integration; some cross-cloud coverage; resource-optimization recommendations ([Microsoft Tech Community, 2025](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/optimizing-resource-allocation-with-microsoft-defender-cspm/4427785)) | Closed source; Azure-centric; per-resource pricing |
| [CoreStack](https://apis.io/providers/corestack/) | CoreStack | Multi-cloud governance combining FinOps, SecOps, and CloudOps in one platform | Closed source; SaaS-only |
| [Stratusphere FinOps](https://stratusgrid.com/secops) | StratusGrid | Multi-account AWS view combining security posture and cost | Closed source; managed-service model |

**Reference framing for the market:** the 2025 Frost Radar for CSPM ([Frost & Sullivan, 2025](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/Frost-Radar-Cloud-Security-Posture-Management-2025.pdf)) confirms that the CSPM segment is consolidating into CNAPP suites that now add cost as an adjacent feature. This trend validates the *problem*, but the resulting products are large commercial platforms rather than developer tools.

## Category 2: Open-source security scanners (cost dimension absent)

| Tool | Language | Focus | Gaps vs. CloudSpendGuard |
|---|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | Python | AWS/Azure/GCP security scanner with hundreds of built-in checks; mature and widely used | No cost analysis; no joint prioritization; report is a flat list of findings |
| [tfsec](https://github.com/aquasecurity/tfsec) | Go | Terraform static analysis for security misconfigurations | IaC-only; no runtime data; no cost dimension |
| [Checkov](https://www.checkov.io/) | Python | IaC static analysis across Terraform, CloudFormation, Kubernetes | Same as tfsec; broader coverage, same scope limitation |
| [KICS](https://kics.io/) | Go | IaC static analysis by Checkmarx | Same as above |
| [cloud-audit](https://www.helpnetsecurity.com/2026/03/11/cloud-audit-open-source-aws-security-scanner/) | Python | Recent open-source AWS security scanner | Security-only; positioned as a Prowler alternative ([HAIT, 2026](https://haitmg.pl/prowler-alternative/)) |
| [Aurelian](https://github.com/praetorian-inc/aurelian) | Multi | Open-source AI-assisted cloud security scanner by Praetorian | Security-only; less mature |

## Category 3: Open-source FinOps and cost tooling (security dimension absent)

| Tool | Language | Focus | Gaps vs. CloudSpendGuard |
|---|---|---|---|
| [Infracost](https://www.infracost.io/) | Go | Cost diffs for Terraform pull requests | No security dimension; requires Terraform |
| [OpenCost](https://www.opencost.io/) | Go | Kubernetes cost allocation (CNCF sandbox project) | Kubernetes-only; no security |
| [Kubecost](https://www.kubecost.com/) | Go | Commercial layer over OpenCost | Kubernetes-only; no security |
| [Show HN: cloud-cost-CLI](https://news.ycombinator.com/item?id=46858093) | Various | Community CLIs for detecting AWS cost waste | Cost-only; no formal analysis or prioritization framework |

## Category 4: Policy-as-code (the closest open-source functional overlap)

**[Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) (a.k.a. c7n)** is the single tool most similar to CloudSpendGuard in *coverage*, though it takes a fundamentally different approach.

- **What it does well:** a YAML policy DSL that can enforce both security rules (for example, "no public S3 buckets") and cost rules (for example, "delete unattached EBS volumes older than 30 days") through the same engine. It is a Cloud Native Computing Foundation project ([CNCF, n.d.](https://www.cncf.io/projects/cloud-custodian/)) with strong adoption across enterprises. Demonstration policies show combined cost and security enforcement ([1Strategy demo](https://github.com/1Strategy/cloud-custodian-demo); [ezyinfra tutorial](https://ezyinfra.dev/blog/enforce-cost-savings-using-cloud-custodian)). A newer subcomponent, [c7n-left](https://cloudcustodian.io/docs/tools/c7n-left.html), extends the engine to IaC.
- **What it does not do:** Cloud Custodian is a **rule-execution engine**, not a **prioritization tool**. Each policy fires independently; there is no unified score that ranks findings by joint cost saving and risk reduction. It also does not include an LLM-assisted remediation module.
- **Deployment posture:** typically deployed as a scheduled job in AWS Lambda or ECS, not as a developer-workstation CLI producing an inspection report.

**Implication for CloudSpendGuard:** Cloud Custodian is the honest reference point to acknowledge in the problem statement. CloudSpendGuard is complementary rather than competitive: Custodian *enforces* policies at scale in production; CloudSpendGuard *analyzes and prioritizes* on a developer laptop before an engineer opens a pull request.

## Category 5: Cloud query engines (adjacent tooling)

| Tool | Approach | Relation to CloudSpendGuard |
|---|---|---|
| [Steampipe](https://steampipe.io/) | SQL query engine for cloud APIs | Could serve as a data source for future CloudSpendGuard analyzers; does not itself score or prioritize |
| [CloudQuery](https://www.cloudquery.io/) | Cloud asset inventory to Postgres | Same as Steampipe |

## Academic and research context

- **Rahman, Parnin, & Williams (2019)** established IaC as a first-class attack surface through empirical analysis of 1,726 Puppet repositories. This work justifies the need for automated static analysis of IaC ([Rahman et al., 2019](https://arxiv.org/abs/1902.02862)).
- **Pearce, Tan, Ahmad, Karri, & Dolan-Gavitt (2023)** demonstrated that large language models can generate reasonable security patches for vulnerable code, but warned of hallucinated fixes that introduce new defects. This work directly motivates CloudSpendGuard's generate-then-verify LLM loop ([Pearce et al., 2023](https://arxiv.org/abs/2112.02125)).
- **FinOps Foundation (2025)** identified optimization and quantifying value as the top FinOps priorities across enterprises managing over USD 69 billion in cloud spend, and documented that FinOps and security ownership are typically siloed ([FinOps Foundation, 2025](https://data.finops.org/2025-report/)).
- **IBM Security (2024)** reported average breach cost at USD 4.88 million, quantifying the security-side impact of the cost that CloudSpendGuard also addresses ([IBM Security, 2024](https://www.ibm.com/reports/data-breach)).

To the best of my knowledge (search conducted 2026-09-06), no published peer-reviewed work presents a joint cost × risk prioritization function combined with an LLM-assisted, verified remediation loop for cloud infrastructure. This is CloudSpendGuard's research contribution.

## Feature comparison matrix

| Capability | Wiz Cloud Cost | Cloud Custodian | Prowler | Infracost | tfsec | **CloudSpendGuard** |
|---|---|---|---|---|---|---|
| Open source | No | Yes (Apache 2.0) | Yes (Apache 2.0) | Partial | Yes (MIT) | Yes (MIT) |
| Local-first CLI (no SaaS required) | No | Yes | Yes | Yes | Yes | Yes |
| Cost analysis | Yes | Yes (rules) | No | Yes | No | Yes |
| Security analysis (runtime) | Yes | Yes (rules) | Yes | No | No | Yes |
| Security analysis (IaC) | Yes | Yes (c7n-left) | No | No | Yes | Yes |
| **Joint cost × risk prioritization score** | Partial (opaque) | No | No | No | No | **Yes (explicit, tunable)** |
| **LLM-assisted remediation with verifier** | Partial (marketed) | No | No | No | No | **Yes (measured)** |
| Report formats | Web UI | JSON, YAML | HTML, JSON | JSON, HTML | JSON, SARIF | Markdown, HTML, JSON |
| Language | Closed | Python | Python | Go | Go | Go |
| Target user | CISO, enterprise | Ops, platform | Auditors | IaC developers | IaC developers | Individual engineers |
| Deployment | SaaS | Lambda, ECS | Local, CI | Local, CI | Local, CI | Local, CI |

## The gap CloudSpendGuard fills

Combining the analysis above, three specific claims are defensible in the Unit 2 problem statement and the Unit 8 final report.

1. **Joint prioritization as an explicit, tunable function.** Commercial platforms bundle cost and security in one dashboard but keep their scoring opaque. Open-source tools address one dimension or execute independent rules. CloudSpendGuard publishes its scoring function `S = α · Savings + β · Risk − γ · BlastRadius` with weights that a user can inspect and adjust, and evaluates precision on labeled fixtures.
2. **Generate-then-verify LLM remediation as a measured feature.** Following Pearce et al. (2023), CloudSpendGuard treats LLM output as untrusted, re-scans every suggested patch with the same analyzer, rejects patches that fail verification, and reports both the acceptance rate and the false-positive rate of the verification step. No open-source cloud tool currently ships this loop as a first-class, benchmarked feature.
3. **Developer-workstation ergonomics.** CloudSpendGuard is designed to run on a laptop, use read-only IAM at runtime, and produce a report an engineer reads before opening a pull request. It fills the gap between IDE-time IaC scanners (tfsec, Checkov) and production-time policy engines (Cloud Custodian, Wiz).

## Suggested Unit 2 related-work paragraph

The following paragraph is drop-in ready for the Unit 2 assignment:

> Several existing tools address parts of the FinOps and cloud security posture problem. Commercial CNAPP platforms such as Wiz Cloud Cost (Wiz, 2024) and Orca Cost Optimization (Orca Security, 2024) have recently added cost-optimization modules on top of their security offerings, but remain closed-source, SaaS-only, and priced for enterprise buyers. In the open-source ecosystem, Cloud Custodian (Cloud Native Computing Foundation, n.d.) provides a YAML policy engine capable of enforcing both cost and security rules, but does so through independent rule execution rather than joint prioritization, and is typically deployed as a production enforcement layer rather than a developer tool. Point tools address only one dimension of the problem: Prowler (Prowler Cloud, 2025) and tfsec (Aqua Security, 2025) cover security, while Infracost (Infracost, 2025) and OpenCost (CNCF, 2025) cover cost. Academic work has established both the necessity of automated IaC security analysis (Rahman et al., 2019) and the feasibility of LLM-assisted vulnerability repair when paired with verification (Pearce et al., 2023). CloudSpendGuard's contribution is a local-first, open-source developer CLI that unifies these two dimensions through an explicit, tunable joint-prioritization function, complemented by an LLM-assisted remediation module with a safety-verification loop, a combination not offered by any existing open-source tool at the time of writing.

## Update schedule

This document will be revisited in Unit 3 (Detailed Design) and Unit 7 (Testing and Evaluation) to reflect any new entrants in the market. Substantive updates are recorded in the change log below.

## Change log

| Date | Change |
|---|---|
| 2026-09-06 | Initial version created for Unit 2 preparation |

## References

Aqua Security. (2025). *tfsec: Security scanner for your Terraform code*. GitHub. https://github.com/aquasecurity/tfsec

Cloud Native Computing Foundation. (n.d.). *Cloud Custodian*. https://www.cncf.io/projects/cloud-custodian/

Cloud Native Computing Foundation. (2025). *OpenCost*. https://www.opencost.io/

FinOps Foundation. (2025). *State of FinOps 2025*. https://data.finops.org/2025-report/

Frost & Sullivan. (2025). *Frost Radar: Cloud Security Posture Management, 2025*. https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/Frost-Radar-Cloud-Security-Posture-Management-2025.pdf

IBM Security. (2024). *Cost of a data breach report 2024*. IBM Corporation. https://www.ibm.com/reports/data-breach

Infracost. (2025). *Infracost documentation*. https://www.infracost.io/

Microsoft. (2025). *Optimizing resource allocation with Microsoft Defender CSPM*. Microsoft Tech Community. https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/optimizing-resource-allocation-with-microsoft-defender-cspm/4427785

Orca Security. (2024). *Orca launches new cloud cost optimization capabilities*. https://orca.security/resources/press-releases/orca-launches-new-cloud-cost-optimization-capabilities/

Pearce, H., Tan, B., Ahmad, B., Karri, R., & Dolan-Gavitt, B. (2023). Examining zero-shot vulnerability repair with large language models. *2023 IEEE Symposium on Security and Privacy (SP)*. https://arxiv.org/abs/2112.02125

Prowler Cloud. (2025). *Prowler: Open-source cloud security scanner*. GitHub. https://github.com/prowler-cloud/prowler

Rahman, A., Parnin, C., & Williams, L. (2019). The seven sins: Security smells in infrastructure as code scripts. *Proceedings of the 41st International Conference on Software Engineering (ICSE '19)*. https://arxiv.org/abs/1902.02862

Wiz. (2024). *Powering cost management and optimization with context*. Wiz Blog. https://www.wiz.io/blog/introducing-wiz-cloud-cost
