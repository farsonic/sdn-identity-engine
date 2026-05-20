FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*


# Create the instance folder explicitly
RUN mkdir -p /app/instance && chmod 777 /app/instance
COPY . .
EXPOSE 8082
EXPOSE 514/udp
EXPOSE 37008/udp
CMD ["python", "app.py"]
