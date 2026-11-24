FROM python:3.12-slim

# Standard library only: nothing to pip install.
WORKDIR /app
COPY whatleaves ./whatleaves

RUN useradd --system --uid 10001 --home-dir /data whatleaves \
 && mkdir -p /data && chown whatleaves /data
USER whatleaves

ENV WL_DB=/data/whatleaves.db \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
CMD ["python", "-m", "whatleaves"]
