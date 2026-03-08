"""Main application for the token validator service."""

import logging
from contextlib import asynccontextmanager
from typing import Annotated

import jwt.exceptions
from ab_core.dependency import Depends, inject
from ab_core.logging.config import LoggingConfig
from ab_core.token_validator.token_validators import TokenValidator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ab_service.token_validator.models.error import TokenValidationErrorReason
from ab_service.token_validator.routes.validate import router as validate_router

logger = logging.getLogger(__name__)


@inject
@asynccontextmanager
async def lifespan(
    _app: FastAPI,
    _token_validator: Annotated[TokenValidator, Depends(TokenValidator, persist=True)],
    logging_config: Annotated[LoggingConfig, Depends(LoggingConfig, persist=True)],
):
    """Lifespan context manager to handle startup and shutdown events."""
    logging_config.apply()
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(validate_router)


@app.exception_handler(jwt.exceptions.ExpiredSignatureError)
async def expired_signature_handler(_request: Request, exc: jwt.exceptions.ExpiredSignatureError):
    """Handle expired token errors."""
    logger.warning("Token validation failed: token has expired", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Token expired", "reason": TokenValidationErrorReason.EXPIRED.value},
    )


@app.exception_handler(jwt.exceptions.InvalidSignatureError)
async def invalid_signature_handler(_request: Request, exc: jwt.exceptions.InvalidSignatureError):
    """Handle invalid signature errors."""
    logger.warning("Token validation failed: invalid signature", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token signature", "reason": TokenValidationErrorReason.INVALID_SIGNATURE.value},
    )


@app.exception_handler(jwt.exceptions.DecodeError)
async def decode_error_handler(_request: Request, exc: jwt.exceptions.DecodeError):
    """Handle token decode errors."""
    logger.warning("Token validation failed: could not decode token", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Token could not be decoded", "reason": TokenValidationErrorReason.DECODE_ERROR.value},
    )


@app.exception_handler(jwt.exceptions.InvalidAudienceError)
async def invalid_audience_handler(_request: Request, exc: jwt.exceptions.InvalidAudienceError):
    """Handle invalid audience errors."""
    logger.warning("Token validation failed: invalid audience", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token audience", "reason": TokenValidationErrorReason.INVALID_AUDIENCE.value},
    )


@app.exception_handler(jwt.exceptions.InvalidIssuerError)
async def invalid_issuer_handler(_request: Request, exc: jwt.exceptions.InvalidIssuerError):
    """Handle invalid issuer errors."""
    logger.warning("Token validation failed: invalid issuer", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token issuer", "reason": TokenValidationErrorReason.INVALID_ISSUER.value},
    )


@app.exception_handler(jwt.exceptions.InvalidIssuedAtError)
async def invalid_issued_at_handler(_request: Request, exc: jwt.exceptions.InvalidIssuedAtError):
    """Handle invalid issued-at claim errors."""
    logger.warning("Token validation failed: invalid iat claim", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={
            "detail": "Invalid token issued-at claim",
            "reason": TokenValidationErrorReason.INVALID_ISSUED_AT.value,
        },
    )


@app.exception_handler(jwt.exceptions.ImmatureSignatureError)
async def immature_signature_handler(_request: Request, exc: jwt.exceptions.ImmatureSignatureError):
    """Handle immature signature errors (nbf/iat in the future)."""
    logger.warning("Token validation failed: token not yet valid", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Token not yet valid", "reason": TokenValidationErrorReason.IMMATURE_SIGNATURE.value},
    )


@app.exception_handler(jwt.exceptions.InvalidAlgorithmError)
async def invalid_algorithm_handler(_request: Request, exc: jwt.exceptions.InvalidAlgorithmError):
    """Handle invalid algorithm errors."""
    logger.warning("Token validation failed: invalid algorithm", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token algorithm", "reason": TokenValidationErrorReason.INVALID_ALGORITHM.value},
    )


@app.exception_handler(jwt.exceptions.InvalidKeyError)
async def invalid_key_handler(_request: Request, exc: jwt.exceptions.InvalidKeyError):
    """Handle invalid key errors."""
    logger.error("Token validation failed: invalid key format", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Token validation configuration error",
            "reason": TokenValidationErrorReason.INVALID_KEY.value,
        },
    )


@app.exception_handler(jwt.exceptions.MissingRequiredClaimError)
async def missing_required_claim_handler(_request: Request, exc: jwt.exceptions.MissingRequiredClaimError):
    """Handle missing required claim errors."""
    logger.warning(f"Token validation failed: missing required claim '{exc.claim}'", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={
            "detail": f"Token missing required claim: {exc.claim}",
            "reason": TokenValidationErrorReason.MISSING_CLAIM.value,
        },
    )


@app.exception_handler(jwt.exceptions.InvalidSubjectError)
async def invalid_subject_handler(_request: Request, exc: jwt.exceptions.InvalidSubjectError):
    """Handle invalid subject errors."""
    logger.warning("Token validation failed: invalid subject", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token subject", "reason": TokenValidationErrorReason.INVALID_SUBJECT.value},
    )


@app.exception_handler(jwt.exceptions.InvalidJTIError)
async def invalid_jti_handler(_request: Request, exc: jwt.exceptions.InvalidJTIError):
    """Handle invalid JTI errors."""
    logger.warning("Token validation failed: invalid jti claim", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token JTI claim", "reason": TokenValidationErrorReason.INVALID_JTI.value},
    )


@app.exception_handler(jwt.exceptions.InvalidTokenError)
async def invalid_token_handler(_request: Request, exc: jwt.exceptions.InvalidTokenError):
    """Catch-all handler for any other InvalidTokenError subclasses."""
    logger.warning("Token validation failed: invalid token", exc_info=exc)
    return JSONResponse(
        status_code=401,
        content={"detail": "Invalid token", "reason": TokenValidationErrorReason.INVALID_TOKEN.value},
    )


@app.exception_handler(jwt.exceptions.PyJWTError)
async def pyjwt_error_handler(_request: Request, exc: jwt.exceptions.PyJWTError):
    """Catch-all handler for any unhandled PyJWT errors."""
    logger.error("Unexpected JWT error", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Token processing error", "reason": TokenValidationErrorReason.UNKNOWN.value},
    )
