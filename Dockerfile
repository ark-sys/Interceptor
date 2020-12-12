FROM ubuntu:18.04

# Install only necessary libraries
RUN apt-get update \
  && apt-get install -y ssh \
    build-essential \
    gcc \
    g++ \
    gdb \
    clang \
    rsync \
    tar \
    python \
    libelf-dev \
    valgrind \
    libtool \
    cmake \
  && apt-get clean


# Taken from - https://docs.docker.com/engine/examples/running_ssh_service/#environment-variables
RUN mkdir /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# expose 22 for ssh server. 7777 for gdb server.
EXPOSE 22 7777

# Create adminuser with password 'password'
RUN useradd -ms /bin/bash admin
RUN echo 'admin:password' | chpasswd

# Upon start, run ssh daemon
CMD ["/usr/sbin/sshd", "-D"]