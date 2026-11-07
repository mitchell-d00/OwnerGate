from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
from .crypto import unb64

Action = Literal["read", "crawl", "index", "summarize", "download", "redistribute"]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,71}$")]
Resource = Annotated[str, Field(pattern=r"^/resources/[a-z0-9][a-z0-9-]{0,63}$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Machine(Strict):
    id: Name
    public_key: Annotated[str, Field(min_length=43, max_length=43)]
    operator: Annotated[str, Field(min_length=1, max_length=200)]
    scopes: Annotated[list[Resource], Field(min_length=1, max_length=32)]
    issued_at: Annotated[int, Field(ge=0, le=4102444800)]
    expires_at: Annotated[int, Field(ge=0, le=4102444800)]

    @model_validator(mode="after")
    def valid(self):
        if self.id.lower() == "unknown" or len(unb64(self.public_key)) != 32:
            raise ValueError("Invalid identity or public key")
        if self.expires_at <= self.issued_at:
            raise ValueError("Expiry must follow issuance")
        return self


class Lifecycle(Strict):
    state: Literal["active", "suspended", "revoked"]


class Rotation(Strict):
    public_key: Annotated[str, Field(min_length=43, max_length=43)]

    @model_validator(mode="after")
    def valid(self):
        if len(unb64(self.public_key)) != 32:
            raise ValueError("Invalid public key")
        return self


class ResourceInput(Strict):
    path: Resource
    title: Annotated[str, Field(min_length=1, max_length=120)]
    content: Annotated[str, Field(min_length=1, max_length=20000)]


class Policy(Strict):
    id: Name
    machine: Name | Literal["*"]
    resource: Resource
    actions: Annotated[list[Action], Field(min_length=1, max_length=6)]
    effect: Literal["allow", "deny"]
    not_before: Annotated[int, Field(ge=0, le=4102444800)]
    expires_at: Annotated[int, Field(ge=0, le=4102444800)]
    restrictions: Annotated[str, Field(max_length=1000)] = ""

    @model_validator(mode="after")
    def valid(self):
        if self.expires_at <= self.not_before:
            raise ValueError("Expiry must follow start")
        return self


class Challenge(Strict):
    machine: Name
    resource: Resource
    action: Action = "read"
