# NanaBanana API Wrapper

This repository contains a FastAPI application that wraps the original
command‑line **NanaBanana Image Generator** script in a web‑friendly API.
It exposes two endpoints for generating images using the
NanaBanana service: one for text‑based prompts and another that uses
a reference image. The behaviour and workflow of the original script
are preserved, including the use of disposable email accounts, OTP
authentication and rotating proxies.

## Features

- **Text‑to‑Image:** Generate a brand new image from a written
  description.
- **Image‑to‑Image:** Transform an existing image according to a
  prompt (e.g. style transfer or modifications).
- **Rotating Proxies:** You must supply a list of proxies with every
  request. The API randomly picks a proxy for each outgoing HTTP
  operation, emulating the rotation logic of the original script.
- **Disposable Inbox:** Each generation request spins up a
  temporary email on [mail.tm](https://mail.tm/) to satisfy the
  service's email verification requirement.
- **Presigned Uploads:** For image‑to‑image tasks the API uploads
  your reference image directly to Cloudflare R2 via a presigned
  URL.

## Usage

Deploy this repository to [Vercel](https://vercel.com/) or any
platform capable of serving Python ASGI applications. The
`vercel.json` configuration included here instructs Vercel to use
Python 3.9 and routes any URL beginning with `/generate/` to
`app.py`.

### Endpoints

#### `POST /generate/text`

Generate an image solely from a text prompt.

**Body JSON:**

```json
{
  "prompt": "قطة بيضاء جميلة تجلس على نافذة…",
  "proxy_list": [
    "host:port:username:password",
    "host2:port2:username:password"
  ],
  "resolution": "2K",          // Optional: 1K, 2K or 4K (default: 2K)
  "aspect_ratio": "Auto",       // Optional: e.g. "16:9" or "Auto"
  "output_format": "png"        // Optional: png, jpg or webp (default: png)
}
```

**Response:**

```json
{
  "image_url": "https://file.nanobanana.org/uploads/..."
}
```

#### `POST /generate/image`

Generate an image from a reference image and a text prompt.

**Body JSON:**

```json
{
  "prompt": "قطة بيضاء جميلة تجلس على نافذة…",
  "image_url": "https://example.com/my-cat.png",
  "proxy_list": [
    "host:port:username:password",
    "host2:port2:username:password"
  ],
  "resolution": "2K",          // Optional
  "aspect_ratio": "Auto",       // Optional
  "output_format": "png"        // Optional
}
```

**Response:** Same as the text endpoint.

### Deploying to Vercel

1. **Create a new Git repository** and add the files in this
   directory (`app.py`, `requirements.txt`, `vercel.json`).
2. **Connect the repository** to Vercel and select the Python
   runtime when prompted.
3. **Deploy.** Vercel will automatically install the dependencies
   listed in `requirements.txt` and serve the FastAPI app.

### Running Locally

To test the API locally you can run it with Uvicorn:

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Then send POST requests to `http://localhost:8000/generate/text` or
`http://localhost:8000/generate/image` as described above.

## Important Notes

- **Proxy Requirement:** Without at least one working proxy the
  generation request will fail. The API enforces this and will
  respond with a 422 validation error if the `proxy_list` is empty.
- **External Dependencies:** This wrapper relies on the behaviour of
  `mail.tm` and `nanobanana.org`. If either service changes its
  endpoints or response format, the code may need to be updated.
- **Timeouts:** Polling for the generated image will abort after
  five minutes if the service does not provide a result.
