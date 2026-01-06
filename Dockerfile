FROM python:3.11-slim

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY PoC_Analyzer.py .
COPY rules/ ./rules/

COPY test_samples.zip .
RUN unzip -P infected test_samples.zip && rm test_samples.zip

RUN useradd -m analyzer
USER analyzer

ENV TERM=xterm-256color
ENV FORCE_COLOR=1
ENTRYPOINT ["python", "PoC_Analyzer.py"]
CMD ["-h"]