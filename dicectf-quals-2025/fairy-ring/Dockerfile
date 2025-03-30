FROM python:slim-bullseye AS app
RUN pip install --no-cache pycryptodome

FROM pwn.red/jail
COPY --from=app / /srv
COPY server.py /srv/app/run
COPY uov.py uov_trapdoor.py flag.txt /srv/app/
COPY keys/* /srv/app/keys/
ENV JAIL_TIME=60 JAIL_MEM=20M JAIL_CPU=500
