# Use Alpine for a lightweight C environment
FROM alpine:3.18

# Install dependencies: build tools, SQLite, microhttpd, OpenSSL
RUN apk add --no-cache build-base sqlite-dev libmicrohttpd-dev openssl-dev

# Set working directory
WORKDIR /app

# Copy source files
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Compile the server
RUN gcc server.c -o server -lmicrohttpd -lsqlite3 -lssl -lcrypto

# Expose the port (Render sets PORT env)
EXPOSE 10000

# Run the server using the PORT environment variable
CMD ["sh", "-c", "./server"]
