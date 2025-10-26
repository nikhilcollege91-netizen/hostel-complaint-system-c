
FROM alpine:3.18
RUN apk add --no-cache build-base libmicrohttpd-dev sqlite-dev
WORKDIR /app
COPY . /app
RUN gcc server.c -o server -lmicrohttpd -lsqlite3
EXPOSE 8080
CMD ["./server"]
