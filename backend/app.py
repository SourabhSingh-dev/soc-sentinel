from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List,Dict,Any
import uvicorn
import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR)

from src.models.inference import ThreatTriageEngine

app = FastAPI(
    title = 'SOC Sentinel Triage API',
    description="Production ML engine for scoring and explaining security incidents.",
    version='1.0.0'
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

def space_tokenizer(x):
    return str(x).split()

engine = None

@app.on_event('startup')
def load_model_enigne():
    global engine
    print("--- BOOTING SOC SENTINEL API ---")
    try : 
        model_path = os.path.join(ROOT_DIR,'models')
        engine = ThreatTriageEngine(model_dir = model_path)
        print("--- ENGINE READY ---")
    except Exception as e:
        print(f"FATAL ERROR loading models: {e}")
        sys.exit(1)

@app.post("/triage")
def triage_incidents(payload : List[Dict[str,Any]]):
    if not payload:
        raise HTTPException(status_code=400,detail="Empty Payload Provided")
    try :
        ranked_queue = engine.triage_batch(payload)
        return{
            "status" : "success",
            "incidents_processed" : len(payload),
            "triage_queue" : ranked_queue
        }
    except Exception as e:
        raise HTTPException(status_code=500,detail=f"Pipeline execution failed {str(e)}")

if __name__ == '__main__':
    uvicorn.run(app,host="0.0.0.0",port=8000)