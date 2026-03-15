FROM python:3.11-slim

WORKDIR /app

# Copy the backend requirements (as they share dependencies like pandas, pyarrow, numpy)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all tools Python module
COPY tools ./tools

ENV PYTHONPATH="/app"

# Command to serve the Log Stream Generator from the dataset
CMD ["python", "-m", "tools.Log_Stream_Generator", "--parquet", "data/cic-collection.parquet", "--max-flows", "500", "--speed", "1", "--demo"]
