"""API 错误类型。"""
from __future__ import annotations


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def not_found(message: str) -> ApiError:
    return ApiError(404, "not_found", message)


def conflict(message: str) -> ApiError:
    return ApiError(409, "conflict", message)


def unprocessable(message: str) -> ApiError:
    return ApiError(422, "unprocessable_entity", message)


def unauthorized(message: str) -> ApiError:
    return ApiError(401, "unauthorized", message)


def forbidden(message: str) -> ApiError:
    return ApiError(403, "forbidden", message)
