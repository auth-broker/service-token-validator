from typing import Annotated

from fastapi import APIRouter
from ab_core.dependency import Depends
from ab_core.token_validator.schema.validated_token import ValidatedOIDCClaims
from ab_core.token_validator.token_validators import TokenValidator

from ..schema import TokenRequest

router = APIRouter(
    prefix="/validate",
    tags=["Token Validator"],
)


@router.post(
    "",
    response_model=ValidatedOIDCClaims,
)
async def validate_token(
    request: TokenRequest,
    token_validator: Annotated[
        TokenValidator,
        Depends(TokenValidator, persist=True),
    ],
):
    return await token_validator.validate(request.token)
