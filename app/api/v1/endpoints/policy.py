from fastapi import APIRouter

from app.core.policy import get_policy

router = APIRouter()


@router.get("/v1/policy", tags=["Policy"])
def get_current_policy() -> dict:
    policy = get_policy()
    return policy.model_dump()