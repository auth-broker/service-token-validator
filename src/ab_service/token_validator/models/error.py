from enum import Enum


class TokenValidationErrorReason(str, Enum):
    EXPIRED = "token_expired"
    INVALID_SIGNATURE = "invalid_signature"
    DECODE_ERROR = "decode_error"
    INVALID_AUDIENCE = "invalid_audience"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_ISSUED_AT = "invalid_issued_at"
    IMMATURE_SIGNATURE = "immature_signature"
    INVALID_ALGORITHM = "invalid_algorithm"
    INVALID_KEY = "invalid_key"
    MISSING_CLAIM = "missing_claim"
    INVALID_SUBJECT = "invalid_subject"
    INVALID_JTI = "invalid_jti"
    INVALID_TOKEN = "invalid_token"
    UNKNOWN = "unknown"
