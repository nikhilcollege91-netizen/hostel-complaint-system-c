# Use a small, secure Linux image with C build tools
FROM alpine:3.18

# Install dependencies for C server and SQLite
RUN apk add --no-cache build-base sqlite-dev libmicrohttpd-dev openssl-dev

# Set working directory
WORKDIR /app

# Copy all project files into the container
COPY . .

# Create uploads directory if not exists
RUN mkdir -p uploads

# Compile the C server
RUN gcc server.c -o server -lmicrohttpd -lsqlite3 -lssl -lcrypto

# Expose port 10000 (Render will use the PORT env variable)
EXPOSE 10000

# Run the compiled server
CMD ["sh", "-c", "./server"]
