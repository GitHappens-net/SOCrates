FROM python:3.11-slim

WORKDIR /app/backend

# Install python dependencies first to cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY . .

# Ensure Python can resolve package imports
ENV PYTHONPATH="/app"

# Expose API port and syslog UDP port
EXPOSE 8000
EXPOSE 514/udp

# Run the backend as a module
WORKDIR /app
CMD ["python", "-m", "backend.main"]
