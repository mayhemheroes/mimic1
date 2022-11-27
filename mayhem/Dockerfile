FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config automake libtool libasound2-dev wget unzip

COPY . /repo
WORKDIR /repo
RUN ./dependencies.sh
RUN ./autogen.sh
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libasound2-dev
COPY --from=builder /install /install
