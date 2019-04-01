FROM alpine:3.9 AS builder
RUN apk add --no-cache rust cargo
WORKDIR /usr/src/greyhound
COPY Cargo.* ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.9
RUN apk add --no-cache libgcc
COPY --from=builder /usr/src/greyhound/target/release/greyhound /usr/bin/
CMD ["greyhound"]
