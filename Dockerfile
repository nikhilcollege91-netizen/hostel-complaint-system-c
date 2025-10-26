FROM alpine:3.18

RUN apk add --no-cache build-base libmicrohttpd-dev sqlite-dev

WORKDIR /app
COPY . /app

# Compile the C server
RUN gcc server.c -o server -lmicrohttpd -lsqlite3

RUN mkdir -p /app/uploads && chmod 755 /app/uploads

EXPOSE 10000
CMD ["./server"]
