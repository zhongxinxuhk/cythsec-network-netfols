/*
 * capture/af_packet/af_packet_capture.c —— CYS-CAP-002：AF_PACKET(TPACKET_V3)
 * 抓包至 pcap 文件的最小程序。
 *
 * 定位：与 capture/pcap/pcap_capture.c 成对，作为吞吐对照实验的「裸 V3 基线」。
 * 生产路径在 dataplane/packet-engine/src/backends/af_packet.cpp（含 V3→V2→recvfrom
 * 降级链与统一后端接口）；本程序**只走 V3**，无降级 —— 它的职责是让基准数字
 * 可以被逐行审计：读的人不需要先理解生产后端的容错分支，就能复核
 * 「mmap 环 + block 退休」与「libpcap 逐包」的差距是不是机制性的。
 *
 * 机器可读汇总行（与 pcap 示例同格式，便于基准脚本统一抓取）：
 *   bench stats backend=af-packet-v3 iface=<名字> packets=<n> bytes=<n>
 *               drops=<n> ifdrops=0 duration_ms=<n>
 *   bench pcap  path=<路径> written=<n>
 *
 * 验收：产物为经典 pcap（纳秒魔数 0xa1b23c4d），Wireshark/tshark 可直接打开。
 * 退出码：0 成功 / 2 用法错误 / 3 socket 或环建立失败（含 EINVAL 的排障提示）
 */
#include <arpa/inet.h> /* htons：缺了它在 aarch64 上是隐式声明，返回值未必是我们要的 */
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* 经典 pcap 写盘：全局头 + 每包记录头（与本仓库 pcap_writer 同口径）。 */
static void pcap_write_global(FILE* f, uint32_t snaplen) {
  /*
   * 经典 pcap 全局头共 24 字节，字段宽度**不是**一律 4 字节：
   *   magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
   * 这里曾把 ver_major/ver_minor 各写成 4 字节，于是整块后移 4 字节：
   * network 字段读出来正好是 snaplen（实测 -s 2112 时 tshark 报
   * "network type 2112 unknown"），任何第三方工具都打不开这个文件。
   * 教训：写盘格式必须用**独立**工具验，自己读自己的产物永远发现不了字段错位。
   */
  uint32_t magic = 0xa1b23c4du; /* 纳秒精度，本机小端序 */
  uint16_t ver_maj = 2, ver_min = 4;
  uint32_t thiszone = 0, sigfigs = 0, network = 1;
  fwrite(&magic, 4, 1, f);
  fwrite(&ver_maj, 2, 1, f);
  fwrite(&ver_min, 2, 1, f);
  fwrite(&thiszone, 4, 1, f);
  fwrite(&sigfigs, 4, 1, f);
  fwrite(&snaplen, 4, 1, f);
  fwrite(&network, 4, 1, f);
}

static void pcap_write_packet(FILE* f, uint32_t sec, uint32_t nsec, uint32_t caplen,
                              uint32_t origlen, const uint8_t* data) {
  fwrite(&sec, 4, 1, f);
  fwrite(&nsec, 4, 1, f);
  fwrite(&caplen, 4, 1, f);
  fwrite(&origlen, 4, 1, f);
  fwrite(data, 1, caplen, f);
}

static void usage(const char* argv0) {
  fprintf(stderr,
          "用法: %s -i <接口> [-t 秒] [-w file.pcap] [-s snaplen] [-b 环字节]\n"
          "  TPACKET_V3 抓包；-t 默认 10；-w 默认 /tmp/af_packet_capture.pcap\n",
          argv0);
}

int main(int argc, char** argv) {
  const char* iface = NULL;
  const char* wpath = "/tmp/af_packet_capture.pcap";
  int seconds = 10;
  uint32_t snaplen = 65535;
  uint32_t ring_bytes = 8u * 1024u * 1024u;
  int opt;
  while ((opt = getopt(argc, argv, "i:t:w:s:b:h")) != -1) {
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
      snaplen = (uint32_t)atoi(optarg);
      break;
    case 'b':
      ring_bytes = (uint32_t)atoi(optarg);
      break;
    default:
      usage(argv[0]);
      return 2;
    }
  }
  if (iface == NULL || seconds <= 0 || snaplen == 0) {
    usage(argv[0]);
    return 2;
  }

  int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    fprintf(stderr, "socket(PF_PACKET) 失败: %s（需要 CAP_NET_RAW：root 或 --cap-add）\n",
            strerror(errno));
    return 3;
  }

  int ver = TPACKET_V3;
  if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
    fprintf(stderr, "setsockopt(PACKET_VERSION=TPACKET_V3) 失败: %s\n", strerror(errno));
    return 3;
  }

  /*
   * 环参数约束（内核 packet_set_ring 会检查，错一项就是 EINVAL）：
   *   block_size 为页的整数倍；frame_size = ALIGN(TPACKET3_HDRLEN) + snaplen；
   *   每块帧数 ≥ 1；frame_nr = block_nr × 每块帧数。
   * 这里取 block = 1MiB，按 snaplen 推 frame_size，再反推实际环字节数
   * （请求值向上取整到整块）—— 与生产后端同一套推导。
   */
  uint32_t page = (uint32_t)sysconf(_SC_PAGESIZE);
  uint32_t block_size = 1024u * 1024u;
  if (block_size % page != 0) {
    block_size = ((block_size / page) + 1) * page;
  }
  uint32_t frame_size = TPACKET_ALIGN(TPACKET3_HDRLEN) + snaplen;
  uint32_t fpb = block_size / frame_size; /* 每块帧数 */
  if (fpb == 0) {
    fprintf(stderr,
            "snaplen=%u 过大：单个帧(%u B)已超过块(%u B)。减小 -s 或增大块（本程序块固定 1MiB）\n",
            snaplen, frame_size, block_size);
    return 3;
  }
  uint32_t block_nr = (ring_bytes + block_size - 1) / block_size;
  if (block_nr < 2) {
    block_nr = 2;
  }
  uint32_t frame_nr = fpb * block_nr;

  struct tpacket_req3 req;
  memset(&req, 0, sizeof(req));
  req.tp_block_size = block_size;
  req.tp_frame_size = frame_size;
  req.tp_block_nr = block_nr;
  req.tp_frame_nr = frame_nr;
  /* V3 的块退休超时：无新包时最迟多久把半满块交给用户态。低流量下决定延迟。 */
  req.tp_retire_blk_tov = 60;
  req.tp_sizeof_priv = 0;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    fprintf(stderr, "setsockopt(PACKET_RX_RING) 失败: %s（检查页对齐/整除约束）\n",
            strerror(errno));
    return 3;
  }

  size_t map_len = (size_t)block_size * block_nr;
  uint8_t* ring =
      (uint8_t*)mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
  if (ring == MAP_FAILED) {
    ring = (uint8_t*)mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
      fprintf(stderr, "mmap 环失败: %s\n", strerror(errno));
      return 3;
    }
  }

  unsigned ifindex = if_nametoindex(iface);
  if (ifindex == 0) {
    fprintf(stderr, "接口 %s 不存在（if_nametoindex: %s）\n", iface, strerror(errno));
    return 3;
  }
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = (int)ifindex;
  if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
    fprintf(stderr, "bind(%s) 失败: %s\n", iface, strerror(errno));
    return 3;
  }

  FILE* out = fopen(wpath, "wb");
  if (out == NULL) {
    fprintf(stderr, "打开 %s 失败: %s\n", wpath, strerror(errno));
    return 3;
  }
  pcap_write_global(out, snaplen);

  uint64_t packets = 0, bytes = 0, written = 0;
  uint32_t current_block = 0;
  int64_t deadline = now_ms() + (int64_t)seconds * 1000;

  while (now_ms() < deadline) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLERR, .revents = 0};
    int remain = (int)(deadline - now_ms());
    if (remain <= 0) {
      break;
    }
    if (poll(&pfd, 1, remain > 200 ? 200 : remain) < 0 && errno != EINTR) {
      break;
    }
    /*
     * V3 的交付单位是**块**：内核把整块交给用户态时置 TP_STATUS_USER，
     * 用户态遍历完把 block_status 写回 TP_STATUS_KERNEL 归还。一次 poll
     * 唤醒可以处理多个块（下面用 for(;;) 连续收）。
     */
    for (;;) {
      struct tpacket_block_desc* bd =
          (struct tpacket_block_desc*)(ring + (size_t)current_block * block_size);
      if (bd->hdr.bh1.block_status & TP_STATUS_USER) {
        // 字段名以 <linux/if_packet.h> 的 struct tpacket_hdr_v1 为准：
        // num_pkts / offset_to_first_pkt。这里曾写成 num_pkts_active /
        // offset_to_first_hp —— 那是**不存在的成员**，于是本示例在任何现代内核上
        // 都编译不过，「机制参照」也就一直没有数据（见 HANDOFF §2.9）。
        struct tpacket_hdr_v1* h1 = &bd->hdr.bh1;
        uint32_t n = h1->num_pkts;
        struct tpacket3_hdr* fh = (struct tpacket3_hdr*)((uint8_t*)bd + h1->offset_to_first_pkt);
        for (uint32_t i = 0; i < n; ++i) {
          uint32_t caplen = fh->tp_snaplen;
          uint32_t origlen = fh->tp_len;
          uint32_t tl = fh->tp_net;
          /* SOCK_RAW：tp_mac 是**相对本帧头**的偏移，不是相对块首 —— 这里曾写成
           * (uint8_t*)bd + tp_mac（相对块首），于是数据指针落在块内随机位置：
           * 包数看着正常、字节数是天文数字（实测 packets=8 bytes=6.28e9）。
           * 示例照样要守越界这条线：帧必须整段落在块内。 */
          uint8_t* frame = (uint8_t*)fh + fh->tp_mac;
          size_t hdr_off = (size_t)((uint8_t*)fh - (uint8_t*)bd);
          size_t block_avail = (size_t)block_size;
          if (hdr_off > block_avail || fh->tp_mac > block_avail || caplen > block_avail ||
              hdr_off + fh->tp_mac + caplen > block_avail || caplen > origlen) {
            fh->tp_status = TP_STATUS_KERNEL;
            if (fh->tp_next_offset == 0) {
              break; /* 异常：非末包却给出 0 偏移，防死循环 */
            }
            fh = (struct tpacket3_hdr*)((uint8_t*)fh + fh->tp_next_offset);
            continue;
          }
          ++packets;
          bytes += origlen;
          pcap_write_packet(out, fh->tp_sec, fh->tp_nsec, caplen, origlen, frame);
          ++written;
          (void)tl;
          fh->tp_status = TP_STATUS_KERNEL;
          if (i + 1 < n) {
            /* tp_next_offset 是**相对当前帧头**的偏移（不是相对块首）。
             * 这里曾写成 (uint8_t*)bd + tp_next_offset —— 于是第二帧起就跳到块内
             * 随机位置：读到的 tp_len/tp_snaplen 是垃圾（实测 packets=8 却
             * bytes=6.28e9），带负载时直接崩。生产实现 af_packet.cpp 用
             * `cur_off_ += next`，口径一致。 */
            if (fh->tp_next_offset == 0) {
              break; /* 非末包却给出 0 偏移：防死循环，宁可少算不多算 */
            }
            fh = (struct tpacket3_hdr*)((uint8_t*)fh + fh->tp_next_offset);
          }
        }
        bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
        current_block = (current_block + 1) % block_nr;
      } else {
        break; /* 下一块还没退休：等下一次 poll */
      }
    }
  }

  struct tpacket_stats st;
  memset(&st, 0, sizeof(st));
  socklen_t slen = sizeof(st);
  uint64_t drops = 0;
  if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &slen) == 0) {
    drops = st.tp_drops;
  }

  fclose(out);
  printf("bench stats backend=af-packet-v3 iface=%s packets=%llu bytes=%llu drops=%llu "
         "ifdrops=0 duration_ms=%d\n",
         iface, (unsigned long long)packets, (unsigned long long)bytes, (unsigned long long)drops,
         seconds * 1000);
  printf("bench pcap path=%s written=%llu\n", wpath, (unsigned long long)written);
  munmap(ring, map_len);
  close(fd);
  return 0;
}
