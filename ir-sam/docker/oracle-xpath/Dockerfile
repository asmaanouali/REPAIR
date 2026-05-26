FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libxml2-dev libxslt1-dev \
 && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir lxml
WORKDIR /opt/oracle
COPY run.py /opt/oracle/run.py
ENTRYPOINT ["python", "/opt/oracle/run.py"]
