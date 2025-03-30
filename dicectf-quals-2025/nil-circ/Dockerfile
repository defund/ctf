FROM rust:slim AS build

WORKDIR /app
COPY ./challenge .
RUN cargo build --release --bin server

FROM pwn.red/jail
COPY --from=build / /srv

RUN cp /srv/app/target/release/server /srv/app
COPY ./aes.txt ./key.txt /srv/app/
COPY ./run.sh /srv/app/run
ENV JAIL_TIME=60 JAIL_MEM=20M JAIL_CPU=500