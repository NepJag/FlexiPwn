FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip netcat-traditional iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install flask
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 5000
HEALTHCHECK --interval=3s --timeout=3s --start-period=10s --retries=5 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python3", "app.py"]
