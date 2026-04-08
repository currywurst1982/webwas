FROM python:3.11-slim

LABEL maintainer="wildfly-monitor" \
      description="WildFly 26 Agent Controller"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY controller.py .
COPY config.yaml .
COPY static/ static/

EXPOSE 8080

CMD ["python", "controller.py"]
