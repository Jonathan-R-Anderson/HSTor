FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y tor && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy_pool.py /
COPY start.sh /

RUN chmod +x /start.sh

EXPOSE 1080
EXPOSE 9050-9150

CMD ["/start.sh"]