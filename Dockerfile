FROM python:3.11-slim

WORKDIR /app

# System deps + Chromium (rarely changes, cached as a single layer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir playwright && \
    playwright install chromium --with-deps && \
    rm -rf /var/lib/apt/lists/*

# Python deps (changes more often, separate layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN rm -rf utils/auth_core/*.py 2>/dev/null || true

EXPOSE 8000
ENV PYTHONUNBUFFERED=1

CMD ["python", "wfxl_openai_regst.py"]