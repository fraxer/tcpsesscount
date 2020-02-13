install pcap

apt install libpcap-dev

build

gcc tcpsesscount.c -o tcpsesscount -Wall -g -lpcap

run

./tcpsesscount ~/dump.cap