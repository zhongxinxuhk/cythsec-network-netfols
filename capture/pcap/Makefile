# capture/pcap — CYS-CAP-001 程序构建入口
# 注：本目录同名 README.md 记录的是「主工程为什么*不*依赖 libpcap」的决策；
# 本程序是**故意**依赖 libpcap 的对照基线（CYS-PKT-008 吞吐命题的另一侧）。
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS += -lpcap

pcap_capture: pcap_capture.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f pcap_capture

.PHONY: clean
