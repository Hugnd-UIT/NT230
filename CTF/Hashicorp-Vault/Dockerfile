FROM ubuntu:20.04

RUN apt-get update && apt-get install -y socat dos2unix gcc libseccomp-dev && rm -rf /var/lib/apt/lists/*
RUN useradd -m ctf
WORKDIR /home/ctf

COPY ./source.c /home/ctf/source.c
RUN gcc -O0 -Wl,-z,relro,-z,now -pie -fPIE -o /home/ctf/hashicorp-vault /home/ctf/source.c -lseccomp
RUN rm /home/ctf/source.c

COPY ./flag.txt /home/ctf/flag.txt
COPY ./start.sh /home/ctf/start.sh

RUN chown -R root:root /home/ctf
RUN chmod 755 /home/ctf
RUN dos2unix /home/ctf/start.sh

RUN chmod 755 /home/ctf/hashicorp-vault
RUN chmod 755 /home/ctf/start.sh
RUN chmod 444 /home/ctf/flag.txt

USER ctf
EXPOSE 1111

CMD ["/home/ctf/start.sh"]