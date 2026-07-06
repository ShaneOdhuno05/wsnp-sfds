import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from logger import Log
from snp_engine.schema import SNPSystem as SNPSystemSchema
from snp_engine.system import SNPSystem

app = FastAPI()
origins = ["http://localhost", "http://localhost:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"Thesis": "SN P Simulator"}


@app.post("/simulate")
async def simulate(system: SNPSystemSchema):
    snpsystem = SNPSystem(system)
    Log.info("Simulating system...")
    snpsystem.simulate()
    Log.info("Finished simulating.")
    Log.info("Sending history...")
    return {"history": snpsystem._history}


@app.post("/simulate/step")
async def simulate_step(system: SNPSystemSchema):
    snpsystem = SNPSystem(system)
    Log.info("Simulating system...")
    snpsystem.simulate_step()
    Log.info("Finished simulating.")
    Log.info("Sending history...")
    return {"history": snpsystem._history}
