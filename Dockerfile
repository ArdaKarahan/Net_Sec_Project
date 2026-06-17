# --- Stage 1: Build liboqs and Compile the Go Binary ---
FROM golang:1.23-bookworm AS builder

# Install build dependencies for liboqs
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clone and compile liboqs natively inside the container
WORKDIR /build-libs
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && make -j$(nproc) \
    && make install
# --- Stage 1: Build liboqs and Compile the Go Binary ---
FROM golang:1.23-bookworm AS builder

# Install build dependencies for liboqs
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clone and compile liboqs natively inside the container
WORKDIR /build-libs
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && make -j$(nproc) \
    && make install

# Create the missing pkg-config file required by the liboqs-go wrapper
RUN mkdir -p /usr/local/lib/pkgconfig && \
    echo "LIBOQS_INCLUDE_DIR=/usr/local/include" > /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "LIBOQS_LIB_DIR=/usr/local/lib" >> /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "Name: liboqs-go" >> /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "Description: pkg-config file for liboqs-go wrapper" >> /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "Version: 0.9.0" >> /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "Cflags: -I\${LIBOQS_INCLUDE_DIR}" >> /usr/local/lib/pkgconfig/liboqs-go.pc && \
    echo "Libs: -L\${LIBOQS_LIB_DIR} -loqs" >> /usr/local/lib/pkgconfig/liboqs-go.pc

# Move to the app directory and copy Go files
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Enable CGO so Go can link with liboqs, then compile the node binary
ENV CGO_ENABLED=1
RUN go build -o /app/blockchain-node ./cmd/node/main.go

# --- Stage 2: Minimal Runtime Environment ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled shared liboqs files from the builder stage
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Update the dynamic linker cache inside the runtime container
RUN ldconfig

# Copy the compiled Go blockchain application
COPY --from=builder /app/blockchain-node /usr/local/bin/blockchain-node

# Expose P2P networking and RPC ports
EXPOSE 8000 8080

ENTRYPOINT ["blockchain-node"]
# Move to the app directory and copy Go files
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Enable CGO so Go can link with liboqs, then compile the node binary
ENV CGO_ENABLED=1
RUN go build -o /app/blockchain-node ./cmd/node/main.go

# --- Stage 2: Minimal Runtime Environment ---
FROM debian:bookworm-slim

# Install runtime dependencies (like iproute2 for tc/netem commands if needed internally)
RUN apt-get update && apt-get install -y \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled shared liboqs files from the builder stage
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Update the dynamic linker cache inside the runtime container
RUN ldconfig

# Copy the compiled Go blockchain application
COPY --from=builder /app/blockchain-node /usr/local/bin/blockchain-node

# Expose P2P networking and RPC ports
EXPOSE 8000 8080

ENTRYPOINT ["blockchain-node"]
