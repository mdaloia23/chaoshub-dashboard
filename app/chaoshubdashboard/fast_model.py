from uuid import UUID, uuid4
from pydantic import BaseModel

from uuid import UUID

class LocalAccount(BaseModel):  # type: ignore

    id: UUID
    account_id: UUID
    username: str
    password: str
