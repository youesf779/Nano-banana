"""
FastAPI wrapper around the original NanaBanana image generator script.

This module exposes two API endpoints which replicate the behaviour of the
command‑line script. Clients can request a new image either from a text
prompt or by providing a reference image URL alongside a prompt. All
requests require a list of rotating proxies; without at least one proxy
defined the API will return an error. The core logic (mail.tm account
creation, OTP login, presigned upload, task submission and polling)
remains unchanged from the original script but has been wrapped in a
synchronous FastAPI application.

Endpoints:
  • POST /generate/text  – Generate a new image from a text prompt.
  • POST /generate/image – Generate a new image from a reference image
                            and a text prompt.

The body of each request must include:
  * prompt (str)            – A description of the desired image.
  * proxy_list (list[str])  – A list of proxies in the form
                               ``host:port:user:password``. A random
                               proxy is chosen for each outbound
                               request.

Optional fields include:
  * resolution (str)        – One of ``1K``, ``2K`` or ``4K``. Defaults
                               to ``2K``.
  * aspect_ratio (str)      – The desired aspect ratio. Defaults to
                               ``Auto``. Accepted values are those
                               supported by the underlying service.
  * output_format (str)     – The desired file format: ``png``, ``jpg``
                               or ``webp``. Defaults to ``png``.
  * image_url (str)         – Only for the ``/generate/image`` endpoint.
                               The URL of the image to be used as a
                               starting point.

On success each endpoint returns JSON containing the final image URL.

Note: This application performs live network operations. If the
underlying services change their API or become unavailable this code
may need to be updated accordingly.
"""

from __future__ import annotations

import os
import random
import re
import string
import time
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, validator


# Base URLs for the NanaBanana service and the temporary email provider.
BASE_URL = "https://nanobanana.org"
MAILTM_URL = "https://api.mail.tm"

# Default headers used for all outbound requests. These mirror the
# headers in the original script to avoid server rejections due to
# unexpected user agents or missing referers.
BASE_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
    "Origin": BASE_URL,
    "Referer": BASE_URL + "/",
}

# Global proxy list used by get_random_proxies(). This is set at
# request time from the incoming payload. A request without proxies
# will be rejected.
PROXY_LIST: List[str] = []


def parse_proxy(proxy_str: str) -> Dict[str, str]:
    """Convert a proxy string into a requests proxy dict.

    The expected format is ``host:port:user:password``. If the input
    string does not conform to this format a ``ValueError`` is raised.

    Args:
        proxy_str: A proxy definition in the format ``host:port:user:password``.

    Returns:
        A dictionary suitable for passing to the ``proxies`` argument of
        ``requests`` calls.
    """
    parts = proxy_str.strip().split(":")
    if len(parts) != 4:
        raise ValueError(
            f"Proxy string must be in the form host:port:user:password, got: {proxy_str!r}"
        )
    host, port, user, password = parts
    url = f"http://{user}:{password}@{host}:{port}"
    return {"http": url, "https": url}


def get_random_proxies() -> Optional[Dict[str, str]]:
    """Select a random proxy from the global ``PROXY_LIST``.

    Returns ``None`` if the list is empty. A new proxy is chosen on
    every call which mirrors the rotation behaviour of the original
    script.
    """
    if not PROXY_LIST:
        return None
    chosen = random.choice(PROXY_LIST)
    return parse_proxy(chosen)


def create_email() -> tuple[str, str, str]:
    """Create a disposable email account using mail.tm.

    Returns a tuple ``(address, password, jwt_token)``. This function
    encapsulates the interactions with mail.tm necessary to
    provision a temporary inbox. A proxy is used if ``PROXY_LIST`` is
    populated.
    """
    proxies = get_random_proxies()
    # Fetch available domains
    domains_resp = requests.get(f"{MAILTM_URL}/domains", timeout=15, proxies=proxies)
    domains_resp.raise_for_status()
    domain = domains_resp.json()["hydra:member"][0]["domain"]
    # Generate random credentials
    user = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    address = f"{user}@{domain}"
    password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    # Register the account
    requests.post(
        f"{MAILTM_URL}/accounts",
        json={"address": address, "password": password},
        timeout=15,
        proxies=proxies,
    )
    # Authenticate to obtain a JWT token for subsequent email reads
    token_resp = requests.post(
        f"{MAILTM_URL}/token",
        json={"address": address, "password": password},
        timeout=15,
        proxies=proxies,
    ).json()
    token = token_resp.get("token")
    if not token:
        raise RuntimeError(f"Failed to obtain JWT token from mail.tm: {token_resp}")
    return address, password, token


def login(email_address: str, mail_jwt: str) -> requests.Session:
    """Authenticate with the NanaBanana service using a disposable email.

    This function retrieves a CSRF token, sends a one‑time password to
    the provided email address, polls the mailbox for the OTP, and
    exchanges it for a session cookie. All HTTP requests use a
    rotating proxy when available. A configured session with cookies
    set is returned.
    """
    # Initialise a session and set static headers
    session = requests.Session()
    session.headers.update(BASE_HEADERS)
    # Apply a proxy to the session if available
    proxies = get_random_proxies()
    if proxies:
        session.proxies.update(proxies)
    # Fetch CSRF token
    csrf_resp = session.get(f"{BASE_URL}/api/auth/csrf", timeout=15)
    csrf_data = csrf_resp.json()
    csrf = csrf_data.get("csrfToken")
    if not csrf:
        raise RuntimeError(f"Failed to obtain CSRF token: {csrf_data}")
    # Request OTP to be sent to the email
    session.post(
        f"{BASE_URL}/api/auth/send-code",
        json={"email": email_address},
        headers={**BASE_HEADERS, "Content-Type": "application/json"},
        timeout=15,
    )
    # Poll mail.tm for the OTP
    mail_headers = {"Authorization": f"Bearer {mail_jwt}"}
    otp: Optional[str] = None
    deadline = time.time() + 90  # Wait up to 90 seconds for the email
    while time.time() < deadline and not otp:
        try:
            mail_proxies = get_random_proxies()
            msgs = requests.get(
                f"{MAILTM_URL}/messages",
                headers=mail_headers,
                timeout=15,
                proxies=mail_proxies,
            ).json()
        except Exception:
            time.sleep(5)
            continue
        for msg in msgs.get("hydra:member", []):
            body = requests.get(
                f"{MAILTM_URL}/messages/{msg['id']}",
                headers=mail_headers,
                timeout=15,
                proxies=mail_proxies,
            ).json()
            # Combine text and HTML to search for the OTP
            html = body.get("html", "")
            if isinstance(html, list):
                html = " ".join(html)
            full_text = body.get("text", "") + " " + html
            m = re.search(r"\b(\d{5,6})\b", full_text)
            if m:
                otp = m.group(1)
                break
        if not otp:
            time.sleep(5)
    if not otp:
        raise RuntimeError("OTP code did not arrive in time")
    # Verify the OTP and establish a session
    verify_resp = session.post(
        f"{BASE_URL}/api/auth/callback/email-code",
        data={
            "email": email_address,
            "code": otp,
            "redirect": "false",
            "csrfToken": csrf,
            "callbackUrl": BASE_URL + "/",
        },
        headers={
            **BASE_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-auth-return-redirect": "1",
        },
        timeout=20,
    )
    if verify_resp.status_code not in (200, 302):
        raise RuntimeError(
            f"OTP verification failed: HTTP {verify_resp.status_code}\n{verify_resp.text[:300]}"
        )
    return session


def upload_image(session: requests.Session, image_url: str) -> str:
    """Upload a reference image to Cloudflare R2 and return its public URL.

    The NanaBanana service does not accept direct uploads to its own
    servers; instead it issues a presigned URL for R2 storage. This
    helper downloads the image at ``image_url``, requests a presigned
    upload from the service, performs the PUT request to R2 and returns
    the resulting public URL. Proxies are rotated on each HTTP call.

    Args:
        session: An authenticated ``requests.Session``.
        image_url: URL of the image to use as a reference.

    Returns:
        A publicly accessible URL to the uploaded image.
    """
    # Download the image bytes
    img_bytes = requests.get(
        image_url, timeout=30, proxies=get_random_proxies()
    ).content
    # Determine content type from extension
    ext_map = {".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}
    ctype = "image/jpeg"
    for ext, ct in ext_map.items():
        if image_url.lower().endswith(ext):
            ctype = ct
            break
    ext = ctype.split("/")[1]
    # Request a presigned upload URL
    presign_resp = session.get(
        f"{BASE_URL}/api/upload",
        params={
            "filename": f"upload.{ext}",
            "contentType": ctype,
            "fileSize": len(img_bytes),
            "pathPrefix": "uploads",
        },
        headers=BASE_HEADERS,
        timeout=15,
    )
    data = presign_resp.json()
    upload_url = (
        data.get("uploadUrl")
        or data.get("signedUrl")
        or data.get("url")
        or data.get("presignedUrl")
    )
    public_url = data.get("publicUrl") or data.get("fileUrl") or data.get("cdnUrl")
    if not upload_url:
        raise RuntimeError(f"No presigned upload URL found in response: {data}")
    # Perform the PUT to R2
    put_resp = requests.put(
        upload_url,
        data=img_bytes,
        headers={
            "Content-Type": ctype,
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/",
        },
        timeout=60,
    )
    if put_resp.status_code not in (200, 204):
        raise RuntimeError(
            f"Failed to upload image: HTTP {put_resp.status_code}"
        )
    # Use returned public URL if available; otherwise derive from the presigned URL
    if public_url and public_url.startswith("http"):
        return public_url
    m = re.search(r"/(uploads/[^?]+)", upload_url)
    if m:
        return f"https://file.nanobanana.org/{m.group(1)}"
    raise RuntimeError("Unable to determine public URL after upload")


def _extract_task_id(data) -> Optional[str]:
    """Extract a task identifier from a variety of server responses."""
    # Check direct keys
    if isinstance(data, dict):
        for k in ("id", "task_id", "taskId", "job_id", "request_id"):
            v = data.get(k)
            if v:
                return str(v)
        # Check nested fields
        for k in ("data", "result", "output", "task", "job"):
            nested = data.get(k)
            if isinstance(nested, dict):
                for nk in ("id", "task_id", "taskId"):
                    nv = nested.get(nk)
                    if nv:
                        return str(nv)
            elif isinstance(nested, (str, int)) and nested:
                return str(nested)
    # When response is a bare string or integer
    if isinstance(data, (str, int)):
        return str(data)
    return None


def submit(
    session: requests.Session,
    prompt: str,
    image_urls: Optional[List[str]],
    resolution: str,
    aspect_ratio: str,
    output_format: str,
) -> str:
    """Submit a generation task to the NanaBanana service.

    Depending on whether ``image_urls`` is provided, the task will be
    dispatched as either a text‑to‑image or image‑to‑image job. The
    service responds with a task identifier which is returned to the
    caller. Errors from the server are converted into exceptions.

    Args:
        session: An authenticated ``requests.Session``.
        prompt: The text prompt describing the desired image.
        image_urls: A list of reference image URLs (or ``None`` for text‑only).
        resolution: Desired resolution (e.g. "1K", "2K", "4K").
        aspect_ratio: Desired aspect ratio (or "Auto").
        output_format: Image format: ``png``, ``jpg`` or ``webp``.

    Returns:
        The task identifier as a string.
    """
    if image_urls:
        gen_type = "image-to-image"
    else:
        gen_type = "text-to-image"
    payload = {
        "model": "nano-banana-pro",
        "type": gen_type,
        "prompt": prompt,
        "resolution": resolution,
        "output_format": output_format,
    }
    if aspect_ratio != "Auto":
        payload["aspect_ratio"] = aspect_ratio
    if image_urls:
        payload["image_input"] = image_urls
    resp = session.post(
        f"{BASE_URL}/api/nano-banana/kie/submit",
        json=payload,
        headers={**BASE_HEADERS, "Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 402:
        raise RuntimeError("Insufficient credit (402 Payment Required)")
    if resp.status_code == 401:
        raise RuntimeError("Unauthorized: session expired (401)")
    if resp.status_code == 429:
        raise RuntimeError("Too many requests (429)")
    if resp.status_code not in (200, 201, 202):
        raise RuntimeError(
            f"Server returned an error: HTTP {resp.status_code}\n{resp.text[:300]}"
        )
    data = resp.json()
    task_id = _extract_task_id(data)
    if not task_id:
        raise RuntimeError(f"Could not extract task ID from response: {data}")
    return task_id


_IMAGE_KEYS = [
    "image_url",
    "imageUrl",
    "image",
    "img_url",
    "output_url",
    "outputUrl",
    "file_url",
    "fileUrl",
    "url",
    "output",
    "result",
    "src",
]


def find_image_url(obj, depth: int = 0) -> Optional[str]:
    """Recursively search a JSON structure for a likely image URL."""
    if depth > 5:
        return None
    if isinstance(obj, str):
        if re.search(r"\.(png|jpg|jpeg|webp)(\?|$)", obj, re.I):
            return obj
        if "r2.cloudflarestorage" in obj or "file.nanobanana" in obj:
            return obj
        return None
    if isinstance(obj, dict):
        for k in _IMAGE_KEYS:
            v = obj.get(k)
            if v and isinstance(v, str) and v.startswith("http"):
                found = find_image_url(v, depth + 1)
                if found:
                    return found
        for v in obj.values():
            found = find_image_url(v, depth + 1)
            if found:
                return found
    if isinstance(obj, list):
        for item in obj:
            found = find_image_url(item, depth + 1)
            if found:
                return found
    return None


def poll(session: requests.Session, task_id: str) -> str:
    """Poll the NanaBanana service until the task is complete.

    This function checks the status of a generation task every six
    seconds for up to five minutes. If a final image URL is found
    within that period it is returned. Should the task fail or the
    timeout be reached an exception is raised.
    """
    deadline = time.time() + 300  # 5 minutes
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            resp = session.get(
                f"{BASE_URL}/api/nano-banana/status/{task_id}",
                headers=BASE_HEADERS,
                timeout=15,
            )
            data = resp.json()
        except Exception:
            time.sleep(6)
            continue
        status = (data.get("status") or data.get("state") or "").lower()
        img_url = find_image_url(data)
        if img_url:
            return img_url
        if status in ("failed", "error", "cancelled"):
            raise RuntimeError(f"Generation failed on server: {status}\n{data}")
        time.sleep(6)
    raise TimeoutError("Generation timed out after 5 minutes without a response")


class BaseRequest(BaseModel):
    prompt: str = Field(..., title="Prompt", description="A description of the desired image")
    proxy_list: List[str] = Field(
        ..., title="Proxy List", description="List of proxies in the form host:port:user:password"
    )
    resolution: str = Field(
        "2K", title="Resolution", description="Desired resolution: 1K, 2K or 4K"
    )
    aspect_ratio: str = Field(
        "Auto",
        title="Aspect Ratio",
        description="Aspect ratio (e.g. 1:1, 9:16, 16:9) or Auto to let the service decide",
    )
    output_format: str = Field(
        "png", title="Output Format", description="png, jpg or webp"
    )

    @validator("proxy_list")
    def validate_proxy_list(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("proxy_list must contain at least one proxy string")
        # Validate basic structure; more detailed validation happens in parse_proxy
        for proxy in value:
            if proxy.count(":") < 3:
                raise ValueError(
                    f"proxy entry '{proxy}' is invalid; expected host:port:user:password"
                )
        return value

    @validator("resolution")
    def validate_resolution(cls, value: str) -> str:
        allowed = {"1K", "2K", "4K"}
        if value not in allowed:
            raise ValueError(f"resolution must be one of {sorted(allowed)}")
        return value

    @validator("output_format")
    def validate_format(cls, value: str) -> str:
        allowed = {"png", "jpg", "webp"}
        if value.lower() not in allowed:
            raise ValueError(f"output_format must be one of {sorted(allowed)}")
        return value.lower()

    @validator("aspect_ratio")
    def validate_aspect_ratio(cls, value: str) -> str:
        # Accept simple ratios or 'Auto'
        if value != "Auto" and not re.match(r"^\d+:\d+$", value):
            raise ValueError(
                "aspect_ratio must be 'Auto' or a ratio in the form A:B (e.g. 16:9)"
            )
        return value


class TextRequest(BaseRequest):
    """Request body for text‑only image generation."""
    # No additional fields
    pass


class ImageRequest(BaseRequest):
    """Request body for image‑guided generation."""
    image_url: str = Field(
        ..., title="Image URL", description="URL of the reference image"
    )


app = FastAPI(title="NanaBanana API Wrapper")


@app.post("/generate/text")
def generate_from_text(req: TextRequest):
    """Generate an image from a text prompt.

    The request body must include a prompt and a list of proxies. Optional
    fields control the resolution, aspect ratio and output format. On
    success the response will contain the URL of the generated image.
    """
    # Set global proxy list for this request
    global PROXY_LIST
    PROXY_LIST = req.proxy_list
    try:
        # Step 1: Obtain a temporary email account
        address, password, mail_jwt = create_email()
        # Step 2: Login to NanaBanana using OTP
        session = login(address, mail_jwt)
        # Step 3: Submit the generation request
        task_id = submit(
            session,
            prompt=req.prompt,
            image_urls=None,
            resolution=req.resolution,
            aspect_ratio=req.aspect_ratio,
            output_format=req.output_format,
        )
        # Step 4: Poll until the image is ready
        img_url = poll(session, task_id)
        return {"image_url": img_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/generate/image")
def generate_from_image(req: ImageRequest):
    """Generate an image from a reference image and a text prompt.

    Clients must provide a prompt, a valid image_url and a list of
    proxies. Optional fields adjust resolution, aspect ratio and
    output format. Returns the URL to the generated image when
    complete.
    """
    global PROXY_LIST
    PROXY_LIST = req.proxy_list
    try:
        # Step 1: Temporary email
        address, password, mail_jwt = create_email()
        # Step 2: Login via OTP
        session = login(address, mail_jwt)
        # Step 3: Upload the reference image
        uploaded_url = upload_image(session, req.image_url)
        # Step 4: Submit the generation request with image
        task_id = submit(
            session,
            prompt=req.prompt,
            image_urls=[uploaded_url],
            resolution=req.resolution,
            aspect_ratio=req.aspect_ratio,
            output_format=req.output_format,
        )
        # Step 5: Poll for completion
        img_url = poll(session, task_id)
        return {"image_url": img_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
