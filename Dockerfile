FROM golang:1.9 as builder

RUN apt-get update \
    && apt-get install flex bison -y \
    && apt-get install libpcap-dev -y \
    && apt-get install ettercap-text-only -y \
    && apt-get clean

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

WORKDIR /go/src/github.com/letitbeat/dp-emulator
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only

COPY sniffer.go ./
RUN go test -v ./...
RUN go build -v -o sniffer sniffer.go

FROM containernet/containernet

RUN pip install pydot

WORKDIR /containernet

RUN curl -O https://raw.githubusercontent.com/letitbeat/dp-generator/master/create_topology.py
RUN curl -O https://raw.githubusercontent.com/letitbeat/dp-generator/master/topology.dot

COPY --from=builder /go/src/github.com/letitbeat/dp-emulator .

CMD ["/bin/bash"]