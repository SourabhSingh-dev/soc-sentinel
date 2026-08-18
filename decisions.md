# Project Decisions


This file records the important technical decisions made during the development of SOC Sentinel, the reasoning behind them, and what happened as a result.


The purpose is not to document every implementation detail, but to preserve the reasoning behind the major choices so that I can later understand why the system looks the way it does.


---


## 1. Use the Microsoft GUIDE dataset without synthetic data


### Decision


I decided to build SOC Sentinel entirely around the real Microsoft GUIDE dataset rather than generating synthetic incidents or assigning manually created risk scores.


### Why


The purpose of the project is to build a realistic security-alert prioritization system. Synthetic data or arbitrary risk formulas would make the project look impressive without actually demonstrating that the model can learn from real SOC telemetry.


The model should learn from actual incident evidence and analyst decisions.


### Outcome


The system is built around real telemetry, real incident labels, and the expert queue-ranking data provided by the dataset.


Risk/probability outputs are intended to come from statistical or ML models rather than manually assigned numbers.


---


## 2. Predict at the incident level, not the evidence level


### Decision


I decided that `IncidentId` would be the fundamental prediction unit.


The raw GUIDE training data contains multiple evidence rows belonging to the same incident, so I cannot train directly on the raw rows.


### Why


An incident may contain many pieces of evidence:


- IP addresses
- files
- accounts
- devices
- alerts
- URLs
- other entities


Training directly on those rows would make the model predict the analyst's decision at the evidence-row level instead of the incident level.


That does not match the actual SOC problem.


### Outcome


The raw evidence is aggregated by `IncidentId` so that each incident becomes one feature vector.


The resulting structure is:


```text
Evidence rows
      ↓
IncidentId aggregation
      ↓
One row per incident
      ↓
ML model
3. Use IncidentGrade as the classification target
Decision

I decided to use IncidentGrade as the target variable.

The three classes are:

FalsePositive
BenignPositive
TruePositive
Why

IncidentGrade represents the human analyst's triage decision and directly corresponds to the classification problem I want to solve.

Outcome

The target is mapped to:

FalsePositive   → 0
BenignPositive  → 1
TruePositive    → 2

Incidents without an IncidentGrade are removed before supervised training.

4. Keep OrgId for ranking, but never use the raw ID as a model feature
Decision

I decided to retain OrgId in the processed incident dataset because it is required for the later queue-ranking problem, but remove it from the classification feature matrix.

Why

The ranking task is organization-specific. An incident ranked first in one organization cannot simply be compared against an incident ranked first in another organization.

However, OrgId itself is an identifier, not a behavioral feature. Feeding the raw organization ID to the model could allow the model to learn organization-specific numeric patterns rather than actual security behavior.

Outcome

OrgId is preserved for grouping/ranking but excluded from X during model training.

5. Drop IncidentId from the model features
Decision

I decided that IncidentId must not be used as a feature.

Why

IncidentId is a primary key, not a behavioral characteristic of an incident.

A model could learn meaningless rules based on the numerical range of the ID rather than learning anything about the incident itself.

Outcome

IncidentId remains available as an identifier but is removed from the ML feature matrix.

6. Remove columns with severe missingness or potential target leakage
Decision

I decided to remove the following columns from the initial feature pipeline:

ResourceType
ActionGrouped
ActionGranular
ThreatFamily
EmailClusterId
AntispamDirection
Roles
SuspicionLevel
LastVerdict
MitreTechniques
Why

EDA showed that several of these columns had substantial missingness, while SuspicionLevel and LastVerdict were particularly problematic because they could represent information generated after or during human triage.

Using post-triage information would allow the model to indirectly see the answer it is supposed to predict.

Outcome

These fields were excluded from the initial modeling pipeline.

7. Convert raw identifiers into behavioral statistics
Decision

I decided not to feed raw identifiers such as IP addresses, usernames, hashes, device IDs, and alert IDs directly into the model.

Instead, I aggregate them into numerical statistics such as unique counts.

Why

The model does not need to memorize that a particular IP or username is associated with an attack.

What matters initially is the behavior represented by those values.

For example:

Raw IPs:
[18150, 27, 360606, 27, 18150]


↓


unique_ip_count = 3

This captures the breadth of the activity without allowing the model to memorize individual identifiers.

Outcome

The incident-level dataset contains numerical footprint features such as:

unique_alert_count
unique_device_count
unique_ipaddress_count
unique_accountname_count
unique_sha256_count
...
8. Keep low-cardinality categorical information instead of assuming it is useless
Decision

I decided that low-cardinality columns such as Category, EntityType, EvidenceRole, and OSFamily should not simply be discarded.

Why

Initially I thought that a small number of unique values might mean a feature was not useful.

That turned out to be the wrong assumption.

Low-cardinality categorical variables can contain highly meaningful information about the type of activity occurring during an incident.

Outcome

These variables were retained in the feature-engineering pipeline.

Initially they were represented through distinct counts. Later analysis showed that simply counting the number of categories loses too much information, leading to the next feature-engineering decision.

9. Convert timestamps into numerical temporal information
Decision

I decided to convert Timestamp from strings into actual datetime values during ingestion and calculate:

incident_duration_seconds

using the difference between the earliest and latest evidence timestamps for an incident.

Why

Raw timestamps are not directly useful to the initial ML model as datetime objects.

At the same time, the duration of an incident is an important behavioral signal.

For example, 500 pieces of evidence generated in a few seconds represents very different behavior from 500 pieces of evidence generated over several days.

Outcome

The ingestion pipeline calculates incident_duration_seconds.

Raw timestamps are excluded from the initial baseline feature matrix.

Temporal features such as hour of day and day of week are reserved for later feature engineering.

10. Replace pandas chunk-based aggregation with Polars
Decision

I decided to use Polars' lazy API for the main ingestion pipeline instead of processing the 2.3 GB CSV through independent pandas chunks.

Why

The original pandas approach introduced a serious correctness problem.

If one incident appeared partly in one chunk and partly in another, aggregating each chunk independently could split the same incident into multiple rows and produce incorrect counts and timestamps.

Memory efficiency was also a concern because the raw dataset is several gigabytes in size.

Outcome

The ingestion pipeline was moved to Polars using lazy execution and a global IncidentId aggregation.

The final pipeline processes the entire dataset while preserving incident-level grouping.

11. Save processed data as Parquet
Decision

I decided to save the processed incident-level dataset as Parquet rather than repeatedly working from the raw CSV.

Why

The raw CSV is large and expensive to parse repeatedly.

Parquet preserves numerical and datetime types and provides a much more convenient intermediate representation for the ML pipeline.

Outcome

The processed dataset is stored under:

data/03_processed/

as a Parquet dataset.

12. Build a deliberately simple baseline before advanced ML
Decision

I decided to build a lightweight Random Forest baseline before attempting more advanced models or extensive hyperparameter tuning.

Why

I need a trustworthy reference point.

If I immediately build a complex model and get a certain score, I will not know whether the model is actually learning useful information or whether the result comes from leakage, feature quality, or model complexity.

The baseline establishes how much predictive signal exists in the current representation.

Outcome

The initial baseline uses:

RandomForestClassifier(
    n_estimators=50,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

The evaluation metric is Macro-F1.

13. Do not tune hyperparameters before fixing the feature representation
Decision

I decided to prioritize feature engineering over hyperparameter tuning.

Why

The initial model was mainly seeing volume and breadth.

For example, both of these could produce similar numerical statistics:

Legitimate administrator:
50 devices touched


Attacker:
50 devices touched

Increasing the number of trees or changing tree depth cannot magically create information that does not exist in the feature space.

Outcome

The next stage of the project focused on extracting behavioral features rather than immediately performing extensive hyperparameter searches.

14. Detect and remove the baseline data leakage
Decision

I decided that the first baseline result could not be treated as valid because IncidentId and OrgId had accidentally remained in the feature matrix.

Why

The model was able to exploit raw identifiers.

This artificially inflated the measured performance and made the original baseline unreliable.

Outcome

After removing the IDs, the honest baseline became:

Macro-F1: 0.6430
True Positive Recall: 0.39
True Positive F1: 0.48

The earlier higher score was discarded as a valid benchmark.

This became an important checkpoint for the project: the benchmark must be based on a leakage-free feature matrix, even if the score becomes worse.

15. Add behavioral features instead of relying only on raw counts
Decision

I decided to introduce behavioral ratios and flags to capture velocity, network spread, and geographic behavior.

The engineered features included:

evidence_per_second
devices_per_account
ips_per_device
is_multinational
is_instantaneous
Why

Raw counts tell the model how much activity occurred, but not how that activity happened.

For example:

500 alerts over 2 seconds

is behaviorally different from:

500 alerts over 3 days

Similarly, an account communicating with dozens of IPs may indicate lateral movement or scanning.

Outcome

The first engineered version produced:

Macro-F1: 0.6459
True Positive Recall: 0.40

Compared with the honest baseline:

Macro-F1: 0.6430
True Positive Recall: 0.39

The improvement was therefore very small.

I concluded that these features were useful signals but were not sufficient by themselves.

16. Use feature importance to decide what to engineer next
Decision

I decided to inspect Random Forest feature importance rather than blindly adding more features.

Why

The model's feature usage provides evidence about what information it is actually relying on.

Outcome

The most important features included:

evidence_per_second
total_evidence_count
unique_state_count
unique_entitytype_count
unique_countrycode_count
unique_city_count
is_multinational

evidence_per_second became the most important feature in the model.

This showed that velocity and geography contained useful signal.

At the same time, unique_category_count was not among the important features.

17. Move from categorical counts to actual categorical threat information
Decision

I decided that simply counting the number of unique categories is not enough.

The next feature-engineering step is to represent the actual threat categories and entity types, rather than reducing them to a single count.

Why

The following two incidents could both have:

unique_category_count = 3

while representing completely different situations:

Spam
Phishing
Informational

versus:

InitialAccess
CredentialDumping
Exfiltration

The count preserves the quantity of categories but destroys their identity.

Outcome

The next engineering direction was defined as unpacking Category and EntityType into explicit boolean/one-hot features such as:

has_category_execution
has_category_exfiltration
...

This is the next major feature-engineering step after the current baseline.

18. Treat the current 0.6459 Macro-F1 as the honest engineered benchmark
Decision

I decided not to exaggerate the improvement from the first feature-engineering iteration.

Why

The honest baseline was:

Macro-F1 = 0.6430

The engineered version was:

Macro-F1 = 0.6459

The True Positive recall improved only from:

0.39 → 0.40

That is too small to claim that the first feature-engineering attempt solved the problem.

Outcome

The current conclusion is:

The first behavioral ratios provide some signal, but volume, velocity, and geographic spread alone are insufficient. The model needs semantic information about what actually happened during the incident.

Current State

At this point, the project has:

Real Microsoft GUIDE data
Incident-level aggregation
Leakage-controlled preprocessing
IncidentGrade as the classification target
Organization information preserved for ranking
Numerical behavioral footprint features
Incident duration
Initial behavioral/velocity/geographic features
A leakage-free Random Forest baseline
Feature-importance analysis
A clear next direction: categorical threat-context features
Current benchmark
Honest Baseline
Macro-F1:          0.6430
True Positive Recall: 0.39


Engineered V2
Macro-F1:          0.6459
True Positive Recall: 0.40

The current bottleneck is not model complexity.

The current bottleneck is feature representation: the model still does not have enough information about the actual type of threat represented by the evidence.

The next step is therefore to unpack Category and EntityType into explicit threat-context features before moving into more advanced modeling or ranking.



One important thing: **I would keep the "Current State" section.** That's the part future-you will actually use. The individual decisions explain *how you got there*; the current state tells you *where you are now*.


And I deliberately **didn't include every one of the 30+ individual aggregation columns as separate de