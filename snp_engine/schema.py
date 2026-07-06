from pydantic import BaseModel, Field
from typing import Literal, Union, Optional

type Neuron = Union[IO, Regular]
type Data = str | int
type Position = dict[Literal["x", "y"], float]


class Synapse(BaseModel):
    source: str = Field(..., alias="from")
    target: str = Field(..., alias="to")
    weight: int


class IO(BaseModel):
    id: str
    type: Literal["input", "output"]
    data: str = Field(..., alias="content")
    position: Optional[Position]


class Regular(BaseModel):
    id: str
    type: Literal["regular"]
    data: int = Field(..., alias="content")
    rules: list[str]
    position: Optional[Position]


class SNPSystem(BaseModel):
    neurons: list[Neuron]
    synapses: list[Synapse]
    expected: Optional[list[Data]] = None
