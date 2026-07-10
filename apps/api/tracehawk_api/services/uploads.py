from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile

from tracehawk_api.config import settings


READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ValidatedUpload:
    filename: str
    text: str
    byte_count: int
    line_count: int


async def read_validated_upload(file: UploadFile) -> ValidatedUpload:
    filename = file.filename or "upload.log"
    _validate_extension(filename)

    chunks: list[bytes] = []
    byte_count = 0
    while chunk := await file.read(READ_CHUNK_BYTES):
        byte_count += len(chunk)
        if byte_count > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds the {settings.max_upload_bytes} byte limit.",
            )
        chunks.append(chunk)

    content = b"".join(chunks)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Uploaded log must be UTF-8 text.") from exc

    line_count = 0 if not text else text.count("\n") + (0 if text.endswith("\n") else 1)
    if line_count > settings.max_upload_lines:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file exceeds the {settings.max_upload_lines} line limit.",
        )
    return ValidatedUpload(
        filename=filename,
        text=text,
        byte_count=byte_count,
        line_count=line_count,
    )


def _validate_extension(filename: str) -> None:
    allowed = {
        extension.strip().lower()
        for extension in settings.allowed_upload_extensions.split(",")
        if extension.strip()
    }
    extension = Path(filename).suffix.lower()
    if extension not in allowed:
        allowed_text = ", ".join(sorted(allowed))
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported upload extension. Allowed extensions: {allowed_text}.",
        )
