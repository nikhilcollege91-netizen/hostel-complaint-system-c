# Stage 1: build C shared lib
FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y build-essential libsqlite3-dev python3 python3-pip
WORKDIR /src
COPY . /src
RUN make

# Stage 2: final image
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /src/libcomplaints.so /app/
COPY . /app
RUN pip install --no-cache-dir flask werkzeug
EXPOSE 5000
CMD ["python", "app.py"]