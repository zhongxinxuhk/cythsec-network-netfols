# capture/af_packet — CYS-CAP-002 AF_PACKET(TPACKET_V3) 抓包至 pcap
# 零依赖（纯内核头文件）。验收：产物可被 Wireshark/tshark 打开。
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

af_packet_capture: af_packet_capture.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f af_packet_capture

.PHONY: clean
