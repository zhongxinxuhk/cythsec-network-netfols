/*
 * capture/pcap/pcap_capture.c —— CYS-CAP-001：libpcap 实时抓包最小程序。
 *
 * 定位（与仓库其他部分的关系）：
 *   本程序**故意**使用 libpcap —— 它是 CYS-PKT-008 验收标准里「pcap live」
 *   对照基线的最小可信实现：AF_PACKET 后端（生产路径 dataplane/packet-engine）
 *   声称「抓包吞吐显著高于 pcap live」，声称就必须有可复现的对照物。
 *   本仓库自身保持零第三方依赖（见 pcap/README.md 的决策一），libpcap 只出现在
 *   这个对照件里，且仅在 Linux 有 libpcap-dev 的环境构建：
 *     apt install libpcap-dev && make
 *
 * 机器可读汇总行（吞吐基准脚本按此抓取，格式稳定不要改）：
 *   bench stats backend=libpcap-live iface=<名字> packets=<n> bytes=<n>
 *               drops=<n> ifdrops=<n> duration_ms=<n>
 *   bench pcap  path=<路径> written=<n>
 *
 * 退出码：0 成功 / 2 用法错误 / 3 打开失败 / 4 落盘失败
 */
#include <pcap/pcap.h>

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void usage(const char* argv0) {
  fprintf(stderr,
          "用法: %s -i <接口> [-t 秒] [-w file.pcap] [-s snaplen]\n"
          "  实时抓包并计数；-t 默认 10 秒；-w 落经典 pcap（Wireshark 可直接打开）\n",
          argv0);
}

int main(int argc, char** argv) {
  const char* iface = NULL;
  const char* wpath = NULL;
  int seconds = 10;
  int snaplen = 65535;
  int opt;
  while ((opt = getopt(argc, argv, "i:t:w:s:h")) != -1) {
    switch (opt) {
    case 'i':
      iface = optarg;
      break;
    case 't':
      seconds = atoi(optarg);
      break;
    case 'w':
      wpath = optarg;
      break;
    case 's':
      snaplen = atoi(optarg);
      break;
    default:
      usage(argv[0]);
      return 2;
    }
  }
  if (iface == NULL || seconds <= 0 || snaplen <= 0) {
    usage(argv[0]);
    return 2;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  /*
   * to_ms=200：libpcap 的读超时。没有它，pcap_next 在无包时会一直阻塞，
   * 本程序按「墙钟时间」终止就无从检查。200ms 是延迟与空转开销的折中；
   * 这正是 pcap live 与 TPACKET 批量语义的差异点之一，基准测试要如实呈现。
   */
  pcap_t* p = pcap_open_live(iface, snaplen, 0 /*promisc*/, 200, errbuf);
  if (p == NULL) {
    fprintf(stderr, "pcap_open_live(%s) 失败: %s\n", iface, errbuf);
    return 3;
  }

  pcap_dumper_t* dump = NULL;
  if (wpath != NULL) {
    dump = pcap_dump_open(p, wpath);
    if (dump == NULL) {
      fprintf(stderr, "pcap_dump_open(%s) 失败: %s\n", wpath, pcap_geterr(p));
      pcap_close(p);
      return 4;
    }
  }

  uint64_t packets = 0, bytes = 0, written = 0;
  int64_t t0 = now_ms();
  int64_t deadline = t0 + (int64_t)seconds * 1000;
  while (now_ms() < deadline) {
    struct pcap_pkthdr hdr;
    const u_char* data = pcap_next(p, &hdr);
    if (data == NULL) {
      continue; /* 超时/无包：pcap_next 的两种非交付都要继续轮询 */
    }
    ++packets;
    bytes += hdr.caplen;
    if (dump != NULL) {
      pcap_dump((u_char*)dump, &hdr, data);
      ++written;
    }
  }
  int64_t dur = now_ms() - t0;

  struct pcap_stat ps;
  memset(&ps, 0, sizeof(ps));
  uint64_t drops = 0, ifdrops = 0;
  /*
   * pcap_stats 在 Linux 上返回内核侧计数（ps_drop：内核缓冲丢包；
   * ps_ifdrop：接口侧丢包）。注意各后端实现对其填充程度不同 ——
   * 「统计为 0」不能直接等价「零丢包」，这正是拿它与 PACKET_STATISTICS
   * 对照时要在报告里写明的口径差异。
   */
  if (pcap_stats(p, &ps) == 0) {
    drops = ps.ps_drop;
    ifdrops = ps.ps_ifdrop;
  }

  printf("bench stats backend=libpcap-live iface=%s packets=%llu bytes=%llu drops=%llu "
         "ifdrops=%llu duration_ms=%lld\n",
         iface, (unsigned long long)packets, (unsigned long long)bytes,
         (unsigned long long)drops, (unsigned long long)ifdrops, (long long)dur);
  if (dump != NULL) {
    pcap_dump_close(dump);
    printf("bench pcap path=%s written=%llu\n", wpath, (unsigned long long)written);
  }
  pcap_close(p);
  return 0;
}
