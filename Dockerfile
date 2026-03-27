FROM python:3.11-slim

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m analyzer && chown -R analyzer:analyzer /app

USER analyzer

COPY --chown=analyzer:analyzer pca.py .
COPY --chown=analyzer:analyzer update_blacklist.py .
COPY --chown=analyzer:analyzer rules/ ./rules/
COPY --chown=analyzer:analyzer test_samples.zip .

RUN unzip -P infected test_samples.zip && rm test_samples.zip

ENV TERM=xterm-256color
ENV FORCE_COLOR=1
ENTRYPOINT ["python", "pca.py"]
CMD ["-h"]