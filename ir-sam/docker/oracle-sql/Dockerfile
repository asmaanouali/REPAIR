FROM python:3.11-slim
RUN pip install --no-cache-dir psycopg2-binary mysql-connector-python
WORKDIR /opt/oracle
COPY run.py /opt/oracle/run.py
ENTRYPOINT ["python", "/opt/oracle/run.py"]
