#define ERR(fmt, ...) do {                                                  \
    dprintf(STDERR_FILENO, fmt "\n" __VA_OPT__(,) __VA_ARGS__);             \
    return -1;                                                              \
} while(0)

#define MAC_TO_CHAR_P(_mac) (char*)(_mac),(char*)(_mac)+1,(char*)(_mac)+2,(char*)(_mac)+3,(char*)(_mac)+4,(char*)(_mac)+5

typedef uint8_t mac_t[6];

typedef struct __attribute__((__packed__)) DeauthRadioHeader {
  uint8_t revision;
  uint8_t pad;
  uint16_t length;
  uint32_t present_flags;
  uint16_t data_rate;
  uint16_t TX_flags;
} deauth_radio_header_t;

typedef struct __attribute__((__packed__)) RadioBody {
  unsigned version:2, type:2, subtype:4, flags:8;
  uint16_t duration;
  mac_t receiver;
  mac_t trasmitter;
  mac_t bss_id;
  unsigned fragment:4, sequence: 12;
} radio_body_t;

typedef struct __attribute__((__packed__)) DeauthPacket {
  size_t length;
  deauth_radio_header_t radio_header;
  radio_body_t radio_body;
  uint16_t reason_code;
} deauth_packet_t;

typedef struct __attribute__((__packed__)) AuthPacket {
  size_t length;
  uint8_t radio_header[24];
  radio_body_t radio_body;
  uint16_t auth_algo;
  uint16_t auth_seq;
  uint16_t status_code;
} auth_packet_t;

typedef struct __attribute__((__packed__)) Packet {
  size_t length;
  uint8_t data[];
} packet_t;

int send_packet(int,packet_t*);
void deauth_attack(int,mac_t*,mac_t*);
void auth_attack(int,mac_t*,mac_t*);
