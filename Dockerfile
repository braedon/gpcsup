FROM python:3.10-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y git mime-support build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY *.py /app/
COPY utils/*.py /app/utils/
COPY gpcsup/*.py /app/gpcsup/
COPY static/* /app/static/
COPY views/*.tpl /app/views/
COPY LICENSE /app/
COPY README.md /app/

ENTRYPOINT ["python", "-u", "main.py"]
