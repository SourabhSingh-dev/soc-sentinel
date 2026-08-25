# SOC Sentinel

### Threat Triage Engine for Security Incident Prioritization

SOC Sentinel is an end-to-end ML system that turns large-scale security telemetry into a **ranked incident queue** — helping a SOC analyst decide **what to investigate first and why**.

It combines **large-scale feature engineering, sparse text representation, XGBoost, probability calibration, SHAP explanations, FastAPI inference, and a React dashboard** into one deployable pipeline.

> **Raw telemetry → Behavioral + Text Features → XGBoost → Calibrated Threat Score → SHAP Evidence → Ranked Queue → API → Dashboard**

---

## Live Demo

**Live Dashboard:** https://soc-sentinel-frontend.onrender.com/

**Backend API:** https://soc-sentinel-vlb1.onrender.com/docs

> The dashboard is connected to the deployed FastAPI inference service and can execute the complete threat-triage pipeline on submitted SOC telemetry.


## The Problem

A SOC can generate far more security events than an analyst can investigate individually.

SOC Sentinel treats the problem as **threat prioritization**, rather than simply binary classification:

> **Given a batch of incidents, rank the most investigation-worthy threats at the top of the queue while providing evidence for the model's decision.**

This makes ranking quality and top-of-queue performance more important than accuracy alone.

---

## What I Built

### 1. Large-Scale Incident Feature Engineering

Processed raw security-event telemetry at the **incident level** using Polars LazyFrames.

Engineered behavioral signals including:

- evidence velocity
- incident duration
- unique devices, accounts, IPs, files and resources
- devices-per-account
- IPs-per-device
- multinational activity
- instantaneous incidents
- threat-category indicators

The pipeline is designed around memory-efficient aggregation rather than repeatedly materializing the full raw dataset.

### 2. Hybrid Feature Representation

Combined structured behavioral features with text information from:

- `AlertTitle`
- `FileName`

Both text fields are transformed with TF-IDF and fused with the dense behavioral features into a **sparse CSR matrix**.

```text
Behavioral Features ─┐
                     ├──► Sparse Feature Matrix ─► XGBoost
AlertTitle TF-IDF ───┤
FileName TF-IDF ─────┘
```

### 3. Model Selection Based on Evidence

I evaluated both **XGBoost and a PyTorch MLP challenger** instead of assuming deep learning would be better.

XGBoost won on the actual objective — ranking and probability quality — so it became the production model.

### 4. Probability Calibration

Raw XGBoost probabilities were calibrated using **Isotonic Regression**.

| Metric | Raw XGBoost | Calibrated XGBoost |
|---|---:|---:|
| PR-AUC | 0.6860 | **0.6898** |
| Brier Score | 0.1189 | **0.1090** |

### 5. Ranking-Aware Evaluation

The system was evaluated around the actual SOC use case:

| Metric | Result |
|---|---:|
| **PR-AUC** | **0.6898** |
| **Precision@1K** | **100%** |
| **Recall@1K** | **10.48%** |
| **Recall@2.5K** | **24.90%** |
| **Recall@9K** | **57.65%** |

These are results on the held-out evaluation set, not guarantees for future production traffic.

### 6. Solving the Calibration Ranking Problem

Isotonic calibration introduced score plateaus: multiple highly confident incidents could receive exactly `1.0`.

That is bad for a ranking system.

Instead of throwing calibration away, I kept:

- **calibrated probability** → primary threat score
- **raw XGBoost probability** → secondary ranking key

```python
triage_queue.sort(
    key=lambda x: (x["threat_score"], x["raw_score"]),
    reverse=True
)
```

This preserves calibrated scores while recovering ranking granularity when calibrated values tie.

### 7. SHAP-Based Evidence

SOC Sentinel uses SHAP to identify the features pushing each incident toward the threat class.

I added a **Reality Filter** so displayed evidence must satisfy:

```text
SHAP contribution > 0
AND
feature is actually present
```

The engine returns the top evidence features with their values and SHAP impact.

```json
{
  "incident_id": 490581,
  "threat_score": 1.0,
  "raw_score": 0.98548,
  "evidence": [
    {
      "feature": "alert_39",
      "value": 1,
      "shap_impact": 5.2933
    }
  ]
}
```

Some alert/file text is intentionally obfuscated by the dataset provider, so those features appear as identifiers such as `alert_39`.

---

## Architecture

```text
                SOC Telemetry
                     │
                     ▼
              Polars LazyFrame
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Behavioral Features      TF-IDF Text
          │                AlertTitle/FileName
          └──────────┬──────────┘
                     ▼
              Sparse CSR Matrix
                     │
                     ▼
                  XGBoost
                /         \
               ▼           ▼
        Raw Probability   Calibration
               │           │
               │           ▼
               │      Threat Score
               │           │
               └─────┬─────┘
                     ▼
              Dual-Score Ranking
                     │
                     ▼
                SHAP Evidence
                     │
                     ▼
               Ranked Queue
                     │
                     ▼
                  FastAPI
                     │
                     ▼
               React Dashboard
```

---

## Dashboard


The React dashboard provides:

- raw JSON telemetry ingestion
- sample payload loading
- client-side validation
- ranked incident queue
- threat severity levels
- calibrated threat scores
- SHAP evidence
- API/network error handling

---

## API

### `POST /triage`

Accepts a JSON telemetry array and returns a ranked queue.

```json
{
  "status": "success",
  "incidents_processed": 2084,
  "triage_queue": [
    {
      "incident_id": 490581,
      "threat_score": 1.0,
      "raw_score": 0.98548,
      "evidence": [...]
    }
  ]
}
```

The final end-to-end test payload processed **2,084 incidents**.

FastAPI also exposes interactive documentation through:

```text
http://localhost:8000/docs
```

---

## Model Comparison

A PyTorch MLP was tested as a challenger:

| Model | PR-AUC | Brier |
|---|---:|---:|
| **Calibrated XGBoost** | **0.6898** | **0.1090** |
| Calibrated MLP | 0.5751 | 0.1208 |

The MLP was faster in the measured GPU environment, but its predictive quality was substantially worse.

**Final choice: XGBoost.**

The important point is not that XGBoost was used — it is that the model was selected from experimental evidence.

---

## Tech Stack

**ML / Data**
- Python
- Polars
- NumPy
- SciPy
- scikit-learn
- XGBoost
- PyTorch
- SHAP

**Backend**
- FastAPI
- Uvicorn
- Pydantic

**Frontend**
- React
- Axios
- Vite
- Lucide React

**Artifacts**
- Joblib
- TF-IDF vectorizers
- XGBoost models
- SHAP TreeExplainer

---

## Project Structure

```text
soc-sentinel/
├── backend/
│   └── app.py
├── frontend/
│   └── src/
│       ├── App.jsx
│       └── App.css
├── src/
│   └── models/
│       └── inference.py
├── models/
├── data/
├── artifacts/
├── notebooks/
├── decisions.md
├── requirements.txt
└── README.md
```

---

## Run Locally

### Backend

```bash
pip install -r requirements.txt

cd backend
python app.py
```

API:

```text
http://localhost:8000
```

Swagger:

```text
http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend communicates with:

```text
POST http://localhost:8000/triage
```

---

## Limitations

This is an ML engineering / portfolio system, not a production SOC platform.

Current limitations include:

- evaluation is based on the Microsoft security-incident dataset
- some provider-supplied text features are obfuscated
- real-world distribution shift has not been established
- the current API uses permissive CORS for development
- authentication, rate limiting and production monitoring are not implemented
- SHAP evidence extraction currently densifies the sparse matrix
- no live SIEM/EDR stream integration is included

A real deployment would require stronger validation, security controls, monitoring, drift detection and production infrastructure.

---

## Dataset & Code

**Dataset:**  
https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction

**Repository:**  
https://github.com/SourabhSingh-dev/soc-sentinel

---

## What Makes SOC Sentinel Different?

The system was built around an operational decision:

> **Prioritize the incidents an analyst should investigate first, and explain the evidence behind that prioritization.**

The final pipeline combines **large-scale data engineering, hybrid feature representation, empirical model selection, probability calibration, ranking-aware inference, constrained explainability, API serving, and an analyst-facing UI** into a single system.
