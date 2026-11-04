FROM python:3.11-slim
COPY analysis /analysis
COPY tools /tools
COPY worker.py /pilot/worker.py
USER 65534:65534
ENTRYPOINT ["python", "-B", "-S", "/pilot/worker.py"]
