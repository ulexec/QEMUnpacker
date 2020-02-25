FROM python:3.6

RUN dpkg --add-architecture i386 && apt-get update
RUN apt-get install libc6-dev libc6-dev:i386 gcc-multilib -y 
RUN apt-get install libc6-armel-cross libc6-dev-armel-cross libncurses5-dev -y 
RUN apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf -y 
RUN apt-get install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi upx -y 
RUN apt-get install python3-pexpect -y
RUN apt-get install qemu-system -y
COPY ./ /home/intezer/
WORKDIR /home/intezer
EXPOSE 4321
RUN make
ENV PYTHONUNBUFFERED=1
CMD ["/usr/bin/python3", "/home/intezer/geu/api/serve.py", "4321"]

