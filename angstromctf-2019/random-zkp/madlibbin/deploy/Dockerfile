FROM python:3-slim

COPY . /ctf
WORKDIR /ctf

RUN pip3 install -r requirements.txt

ENV FLAG actf{traversed_the_world_and_the_seven_seas}

EXPOSE 3000
LABEL options='{"network":"madlibbin"}'

CMD ["gunicorn", "-c", "gunicorn.conf", "madlibbin:app"]