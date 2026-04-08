FROM python:3.11-slim

LABEL maintainer="wildfly-monitor" \
      description="WildFly 26 Log Monitoring Agent"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wildfly_agent.py .
COPY config.yaml .

# In real deployments, mount the actual WildFly log directory:
#   -v /opt/wildfly-26.1.3.Final/standalone/log:/logs:ro
# and set WILDFLY_LOG_PATH=/logs/server.log

CMD ["python", "wildfly_agent.py", "config.yaml", "--simulate"]
