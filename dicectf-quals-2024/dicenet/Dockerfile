FROM rust:slim as build

WORKDIR /app
COPY ./challenge .
RUN cargo build --release --bin server

FROM pwn.red/jail
COPY --from=build / /srv
RUN cp /srv/app/target/release/server /srv/app
COPY ./challenge/net/model.json ./challenge/net/weights.json /srv/app/
COPY ./run.sh /srv/app/run
ENV JAIL_TIME=60 JAIL_MEM=100M JAIL_CPU=1000
