FROM ubuntu:xenial

RUN apt-get -y update
RUN apt-get -y install openssh-server

RUN mkdir /var/run/sshd
RUN sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config

RUN adduser --system ctf

ADD flag.txt /etc/motd
RUN sed -i "s/PrintLastLog yes/PrintLastLog no/g" /etc/ssh/sshd_config

RUN mkdir -p /home/ctf/.ssh
ADD id_ecdsa.pub /home/ctf/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
