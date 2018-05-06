// PlayStation 4 Discovery and Wake-up Utility
// Copyright (C) 2014 Darryl Sokoloski <darryl@sokoloski.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "sha1.h"
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

#include <sys/random.h>


#define _VERSION            "1.1"
#define _DST_PORT           987
#define _PROBES             6

#define _DDP_VERSION        "00020020"
#define _DDP_CLIENTTYPE     "a"
#define _DDP_AUTHTYPE       "C"
#define _DDP_MODEL          "a"
#define _DDP_APPTYPE        "c"

#define _EXIT_SUCCESS       0
#define _EXIT_BADOPTION     1
#define _EXIT_NOUSERCRED    2
#define _EXIT_SOCKET        3
#define _EXIT_NOHOSTADDR    4
#define _EXIT_BADHOSTADDR   5
#define _EXIT_DEVNOTFOUND   6
#define _EXIT_HOSTNOTFOUND  7


#define LOGIN_REQ 0x1e
#define LOGIN_RSP 0x07
#define APP_START_REQ 0x0a
#define APP_START_RSP 0x0b
#define HELLO_REQ 0x6f636370
#define HANDSHAKE_REQ 0x20
#define STATUS_REQ 0x14
#define STANDBY_REQ 0x1a
#define STANDBY_RSP 0x1b

#define LOGIN_SUCCESS 0x00
#define PASSCODE_NEEDED 0x14
#define PIN_NEEDED 0x16
#define PIN_INVALID 0x0e /* ?? */

struct ddp_reply
{
    short code;
    char *host_id;
    char *host_name;
    char *host_type;
    char *running_app_name;
    char *running_app_titleid;
    char *version;
    short host_request_port;
};

struct hello_request
{
    uint32_t length;
    uint32_t type;
    uint32_t version;
    uint8_t seed[16];
};

struct hello_response
{
    uint32_t length;
    uint32_t type;
    uint32_t version;
    uint8_t dummy[8];
    uint8_t seed[16];
};

/* RSA pkcs8 public key */
#define PUBLIC_KEY \
"-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxfAO/MDk5ovZpp7xlG9J\n" \
"JKc4Sg4ztAz+BbOt6Gbhub02tF9bryklpTIyzM0v817pwQ3TCoigpxEcWdTykhDL\n" \
"cGhAbcp6E7Xh8aHEsqgtQ/c+wY1zIl3fU//uddlB1XuipXthDv6emXsyyU/tJWqc\n" \
"zy9HCJncLJeYo7MJvf2TE9nnlVm1x4flmD0k1zrvb3MONqoZbKb/TQVuVhBv7SM+\n" \
"U5PSi3diXIx1Nnj4vQ8clRNUJ5X1tT9XfVmKQS1J513XNZ0uYHYRDzQYujpLWucu\n" \
"ob7v50wCpUm3iKP1fYCixMP6xFm0jPYz1YQaMV35VkYwc40qgk3av0PDS+1G0dCm\n" \
"swIDAQAB\n" \
"-----END PUBLIC KEY-----"
/*
static const uint8_t public_key[] = 
{
  0xc5,0xf0,0x0e,0xfc,0xc0,0xe4,0xe6,0x8b,0xd9,0xa6,0x9e,0xf1,0x94,0x6f,0x49,0x24,
  0xa7,0x38,0x4a,0x0e,0x33,0xb4,0x0c,0xfe,0x05,0xb3,0xad,0xe8,0x66,0xe1,0xb9,0xbd,
  0x36,0xb4,0x5f,0x5b,0xaf,0x29,0x25,0xa5,0x32,0x32,0xcc,0xcd,0x2f,0xf3,0x5e,0xe9,
  0xc1,0x0d,0xd3,0x0a,0x88,0xa0,0xa7,0x11,0x1c,0x59,0xd4,0xf2,0x92,0x10,0xcb,0x70,
  0x68,0x40,0x6d,0xca,0x7a,0x13,0xb5,0xe1,0xf1,0xa1,0xc4,0xb2,0xa8,0x2d,0x43,0xf7,
  0x3e,0xc1,0x8d,0x73,0x22,0x5d,0xdf,0x53,0xff,0xee,0x75,0xd9,0x41,0xd5,0x7b,0xa2,
  0xa5,0x7b,0x61,0x0e,0xfe,0x9e,0x99,0x7b,0x32,0xc9,0x4f,0xed,0x25,0x6a,0x9c,0xcf,
  0x2f,0x47,0x08,0x99,0xdc,0x2c,0x97,0x98,0xa3,0xb3,0x09,0xbd,0xfd,0x93,0x13,0xd9,
  0xe7,0x95,0x59,0xb5,0xc7,0x87,0xe5,0x98,0x3d,0x24,0xd7,0x3a,0xef,0x6f,0x73,0x0e,
  0x36,0xaa,0x19,0x6c,0xa6,0xff,0x4d,0x05,0x6e,0x56,0x10,0x6f,0xed,0x23,0x3e,0x53,
  0x93,0xd2,0x8b,0x77,0x62,0x5c,0x8c,0x75,0x36,0x78,0xf8,0xbd,0x0f,0x1c,0x95,0x13,
  0x54,0x27,0x95,0xf5,0xb5,0x3f,0x57,0x7d,0x59,0x8a,0x41,0x2d,0x49,0xe7,0x5d,0xd7,
  0x35,0x9d,0x2e,0x60,0x76,0x11,0x0f,0x34,0x18,0xba,0x3a,0x4b,0x5a,0xe7,0x2e,0xa1,
  0xbe,0xef,0xe7,0x4c,0x02,0xa5,0x49,0xb7,0x88,0xa3,0xf5,0x7d,0x80,0xa2,0xc4,0xc3,
  0xfa,0xc4,0x59,0xb4,0x8c,0xf6,0x33,0xd5,0x84,0x1a,0x31,0x5d,0xf9,0x56,0x46,0x30,
  0x73,0x8d,0x2a,0x82,0x4d,0xda,0xbf,0x43,0xc3,0x4b,0xed,0x46,0xd1,0xd0,0xa6,0xb3
};*/


 
struct handshake_request
{
    uint32_t length;
    uint32_t type;
    uint8_t key[256];
    uint8_t seed[16];
};

struct login_request
{
    uint32_t length;
    uint32_t type;
    uint32_t pin_code;
    uint32_t magic_number;
    uint8_t account_id[64];
    uint8_t app_label[256];
    uint8_t os_version[16];
    uint8_t model[16];
    uint8_t pass_code[16];
};

struct login_response
{
    uint32_t length;
    uint32_t type;
    uint32_t status;
    uint32_t unknown2;
};

struct status_request
{
    uint32_t length;
    uint32_t type;
    uint32_t status;
};

struct standby_request
{
    uint32_t length;
    uint32_t type;
    uint8_t padding[8];
};


struct standby_response
{
    uint32_t length;
    uint32_t type;
    uint32_t status;
    uint32_t padding;
};

struct app_request
{
    uint32_t length;
    uint32_t type;
    uint8_t app_id[16];
    uint8_t padding[8];
};


struct app_response
{
    uint32_t length;
    uint32_t type;
    uint32_t status;
    uint32_t padding;
};

static char *buffer = NULL, *iface = NULL;
static char *pkt_input, *pkt_output, *json_buffer;
static char *host_remote = NULL, *cred = NULL;
static int rc, broadcast = 0, probe = 0, json = 0, verbose = 0;
static int sd = -1;
static short port_local = INADDR_ANY, port_remote = _DST_PORT;
static struct ddp_reply *reply = NULL;
static struct sockaddr_in sa_local, sa_remote;
static int login=0, wakeup=0, standby=0;
static int sockfd = -1;
static long page_size;
static uint8_t randomseed[16];
static uint8_t seed[16];
static uint8_t ive[16];
static uint8_t ivd[16];

static int ddp_parse(char *buffer, struct ddp_reply *reply)
{
    char *c, *sp1, *sp2;
    char *p = buffer, *token = NULL, *key, *value;

    for (p = buffer; ; p = NULL) {
        token = strtok_r(p, "\n", &sp1);
        if (token == NULL) break;

        if (token[0] == 'H' && token[1] == 'T' &&
            token[2] == 'T' && token[3] == 'P') {
            for (p = token + 8; *p == ' '; p++);
            for (c = p; isdigit(*p); p++);
            *p = '\0'; reply->code = (short)atoi(c);
            continue;
        }

        p = token;
        key = strtok_r(p, ":", &sp2);
        if (key == NULL) continue;

        p = NULL;
        value = strtok_r(p, ":", &sp2);
        if (value == NULL) continue;

        if (!strcmp(key, "host-id"))
            reply->host_id = strdup(value);
        else if (!strcmp(key, "host-type"))
            reply->host_type = strdup(value);
        else if (!strcmp(key, "host-name"))
            reply->host_name = strdup(value);
        else if (!strcmp(key, "host-request-port"))
            reply->host_request_port = (short)atoi(value);
        else if (!strcmp(key, "running-app-name"))
            reply->running_app_name = strdup(value);
        else if (!strcmp(key, "running-app-titleid"))
            reply->running_app_titleid = strdup(value);
    }

    if (reply->code == 0) return 1;

    return 0;
}

static void ddp_free(struct ddp_reply *reply)
{
    if (reply == NULL) return;
    if (reply->host_id != NULL) free(reply->host_id);
    if (reply->host_name != NULL) free(reply->host_name);
    if (reply->host_type != NULL) free(reply->host_type);
    if (reply->running_app_name != NULL) free(reply->running_app_name);
    if (reply->running_app_titleid != NULL) free(reply->running_app_titleid);
    if (reply->version != NULL) free(reply->version);
}

static int iface_get_bcast_addr(const char *iface, struct sockaddr_in *sa)
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "Error getting interface addresses: %s\n", strerror(errno));
        return 1;        
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, iface)) continue;

        memcpy(&sa->sin_addr,
            &((struct sockaddr_in *)ifa->ifa_dstaddr)->sin_addr,
            sizeof(struct in_addr));

        break;
    }

    freeifaddrs(ifaddr);

    return 0;
}

static void json_output(struct ddp_reply *reply)
{
    char *p = json_buffer;

    const char *host_id = p, *host_name = p, *host_type = p;
    const char *running_app_name = p, *running_app_titleid = p;
    const char *version = p;

    sprintf(p, "null");
    p += strlen(json_buffer) + 1;

    if (reply->host_id != NULL) {
        host_id = p;
        sprintf(p, "\"%s\"", reply->host_id);
        p += strlen(p) + 1;
    }
    if (reply->host_name != NULL) {
        host_name = p;
        sprintf(p, "\"%s\"", reply->host_name);
        p += strlen(p) + 1;
    }
    if (reply->host_type != NULL) {
        host_type = p;
        sprintf(p, "\"%s\"", reply->host_type);
        p += strlen(p) + 1;
    }
    if (reply->running_app_name != NULL) {
        running_app_name = p;
        sprintf(p, "\"%s\"", reply->running_app_name);
        p += strlen(p) + 1;
    }
    if (reply->running_app_titleid != NULL) {
        running_app_titleid = p;
        sprintf(p, "\"%s\"", reply->running_app_titleid);
        p += strlen(p) + 1;
    }
    if (reply->version != NULL) {
        version = p;
        sprintf(p, "\"%s\"", reply->version);
        p += strlen(p) + 1;
    }

    memcpy(p, &reply->code, sizeof(short));
    p += sizeof(short);
    memcpy(p, &reply->host_request_port, sizeof(short));
    p += sizeof(short);

    sha1 sha1_ctx;
    sha1_init(&sha1_ctx);
    sha1_write(&sha1_ctx, json_buffer, (size_t)(p - json_buffer));

    uint8_t *sha1_binary = sha1_result(&sha1_ctx);

    char sha1_fingerprint[SHA1_HASH_LENGTH * 2 + 1];
    p = sha1_fingerprint;

    for (int i = 0; i < SHA1_HASH_LENGTH; i++, p += 2)
        sprintf(p, "%02x", sha1_binary[i]);

    fprintf(stdout,
        "{\"code\":%hd,\"host_id\":%s,\"host_name\":%s,\"host_type\":%s,"
        "\"running_app_name\":%s,\"running_app_titleid\":%s,"
        "\"version\":%s,\"host_request_port\":%hd,\"timestamp\":%ld,"
        "\"fingerprint\":\"%s\"}\n",
        reply->code, host_id, host_name, host_type,
        running_app_name, running_app_titleid,
        version, reply->host_request_port, (long)time(NULL),
        sha1_fingerprint
    );
}

void onexit(void)
{
    if (host_remote != NULL) free(host_remote);
    if (cred != NULL) free(cred);
    if (sd > -1) close(sd);
    if (buffer != NULL) free(buffer);
    if (iface != NULL) free(iface);
    if (reply != NULL) {
        ddp_free(reply);
        free(reply);
    }
}

static void print_version()
{
    fprintf(stderr, "ps4-wake v%s\n", _VERSION);
}

static void usage(int rc)
{
    fprintf(stderr, "Help\n");
    print_version();
    fprintf(stderr, " Probe:\n");
    fprintf(stderr, "  -P, --probe\n    Probe network for devices.\n");
    fprintf(stderr, " Wake:\n");
    fprintf(stderr, "  -W, --wake\n    Wake device.\n");
    fprintf(stderr, " Standby:\n");
    fprintf(stderr, "  -S, --standby\n    put the device in standby mode.\n");
    fprintf(stderr, " Options:\n");
    fprintf(stderr, "  -c, --credential <user-credential>\n    use specified user credential (needed by wake and login).\n");
    fprintf(stderr, "  -l, --login\n    login to the device.\n");
    fprintf(stderr, "  -p, --passcode\n    use passcode when login (must be used with login option).\n");
    fprintf(stderr, "  -B, --broadcast\n    Send broadcasts.\n");
    fprintf(stderr, "  -L, --local-port <port address>\n    Specifiy a local port address.\n");
    fprintf(stderr, "  -H, --remote-host <host address>\n    Specifiy a remote host address.\n");
    fprintf(stderr, "  -R, --remote-port <port address>\n    Specifiy a remote port address (default: %d).\n", _DST_PORT);
    fprintf(stderr, "  -I, --interface <interface>\n    Bind to interface.\n");
    fprintf(stderr, "  -j, --json\n    Output JSON.\n");
    fprintf(stderr, "  -v, --verbose\n    Enable verbose messages.\n");

    exit(rc);
}
static int ddp_send(const char* cmd)
{
    ssize_t bytes;
    
    sprintf(pkt_output,
        "%s * HTTP/1.1\n"
        "client-type:%s\n"
        "auth-type:%s\n"
        "model:%s\n"
        "app-type:%s\n"
        "user-credential:%s\n"
        "device-discovery-protocol-version:%s\n",
        cmd, _DDP_CLIENTTYPE, _DDP_AUTHTYPE, _DDP_MODEL, _DDP_APPTYPE, cred, _DDP_VERSION);

    if (verbose) fprintf(stderr, "Sending %s...\n", cmd);

    sa_remote.sin_port = htons(port_remote);
    bytes = sendto(sd, pkt_output, strlen(pkt_output), 0,
        (struct sockaddr *)&sa_remote, sizeof(struct sockaddr_in));
    if (bytes < 0) {
        fprintf(stderr, "Error writing packet: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    return _EXIT_SUCCESS;
}

static RSA * createRSA(char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return NULL;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
 
    return rsa;
}

static int connect_device()
{
    int ret;
    int i;
    struct sockaddr_in dev_addr;
    struct hello_response hello_rsp;
    struct hello_request hello_req;
    struct handshake_request handshake_req;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    memset(&dev_addr, '0', sizeof(dev_addr)); 
    dev_addr.sin_addr.s_addr  = sa_remote.sin_addr.s_addr;
    dev_addr.sin_port = htons(997); 
    dev_addr.sin_family = AF_INET;
    if (verbose) fprintf(stderr, "Connecting...\n");
   
    ret = connect(sockfd, (struct sockaddr *)&dev_addr, sizeof(dev_addr));
    if (ret < 0) {
        fprintf(stderr, "Error connect: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    if (verbose) fprintf(stderr, "Sending Hello\n");
    
    hello_req.length = sizeof(hello_req);
    hello_req.type = HELLO_REQ;
    hello_req.version = 0x20000;
    memset(hello_req.seed, 0, sizeof(hello_req.seed));
    ret = write(sockfd, (uint8_t*)&hello_req, sizeof(hello_req));
    if (ret != sizeof(hello_req)) {
        fprintf(stderr, "Error sending Hello, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    ret = read(sockfd, &hello_rsp, sizeof(hello_rsp));
    if (ret != sizeof(hello_rsp)) {
        fprintf(stderr, "Error reading Hello response, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    if (verbose) fprintf(stderr, "rsp: len=%d, type=0x%x, version=0x%x\n", hello_rsp.length, hello_rsp.type, hello_rsp.version);
    if(hello_rsp.length != sizeof(hello_rsp))
        fprintf(stderr, "Invalid hello response packet size\n");
    
    if(verbose) {
        fprintf(stderr, "Seed: ");
        for(i=0;i<sizeof(hello_rsp.seed);i++)
            fprintf(stderr, "%02x ", ((uint8_t*)&hello_rsp.seed)[i]);
        fprintf(stderr,"\n");
    }
    memcpy(seed, hello_rsp.seed, sizeof(seed));
    /* AES init */
    
    handshake_req.length = sizeof(handshake_req);
    handshake_req.type = HANDSHAKE_REQ;
    
    memcpy(handshake_req.seed, seed, sizeof(seed));
    
    if(getrandom(randomseed, 16, 0) != 16) {
        fprintf(stderr, "Error: cannot get random\n");
        return _EXIT_SOCKET;
    }
    RSA * rsa = createRSA(PUBLIC_KEY, 1);
    ret = RSA_public_encrypt(sizeof(randomseed),randomseed, handshake_req.key, rsa, RSA_PKCS1_OAEP_PADDING);
    if(ret != 256) {
        fprintf(stderr, "encrypt failed %d\n", ret);
        return _EXIT_SOCKET;
    }
    
    if (verbose) fprintf(stderr, "Sending Handshake\n");
    
    ret = write(sockfd, &handshake_req, sizeof(handshake_req));
    if (ret != sizeof(handshake_req)) {
        fprintf(stderr, "Error sending handshake, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    return _EXIT_SUCCESS;
}

static int send_login(const char* passcode)
{
    int ret;
    
    AES_KEY   enc_key;
    AES_KEY   dec_key;
    struct login_request login_req;
    struct login_response login_rsp;
    //struct status_request status_req;
    
    login_req.length = sizeof(login_req);
    login_req.type = LOGIN_REQ;
    login_req.pin_code = 0x00;
    login_req.magic_number = 0x00000201;
    strncpy((char*)login_req.account_id, cred, 64);
    strncpy((char*)login_req.app_label, "Playstation", 256);
    strncpy((char*)login_req.os_version, "4.4", 16);
    strncpy((char*)login_req.model, "PS4-Wake 2", 16);
    if(passcode)
        strncpy((char*)login_req.pass_code, passcode, 16);
    else
        memset(login_req.pass_code, 0, 16);
    
    
    AES_set_encrypt_key(randomseed, sizeof(randomseed)*8, &enc_key);
    memcpy(ive, seed, sizeof(ive));
    AES_cbc_encrypt((uint8_t*)&login_req, (uint8_t*)&login_req, sizeof(login_req), &enc_key, ive, AES_ENCRYPT);
    
    if (verbose) fprintf(stderr, "Sending login\n");
    
    ret = write(sockfd, &login_req, sizeof(login_req));
    if (ret != sizeof(login_req)) {
        fprintf(stderr, "Error sending login, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    ret = read(sockfd, (uint8_t*)&login_rsp, sizeof(login_rsp));
    if (ret <=0) {
        fprintf(stderr, "Error reading login response, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    AES_set_decrypt_key(randomseed, sizeof(randomseed)*8, &dec_key);
    memcpy(ivd, seed, sizeof(ivd));
    AES_cbc_encrypt((uint8_t*)&login_rsp, (uint8_t*)&login_rsp, sizeof(login_rsp), &dec_key, ivd, AES_DECRYPT);
    
    if(login_rsp.length != sizeof(login_rsp))
        fprintf(stderr, "Invalid login response size\n");
    if(login_rsp.type != LOGIN_RSP)
        fprintf(stderr, "Invalid login response type\n");
    
    switch(login_rsp.status)
    {
        case LOGIN_SUCCESS:
            fprintf(stderr, "login success\n");
        break;
        case PASSCODE_NEEDED:
            fprintf(stderr, "passcode needed\n");
            return _EXIT_NOUSERCRED;
        case PIN_NEEDED:
            fprintf(stderr, "pincode needed\n");
            return _EXIT_NOUSERCRED;
        case PIN_INVALID:
            fprintf(stderr, "pincode invalid?\n");
            return _EXIT_NOUSERCRED;
        default:
            fprintf(stderr, "Unknown error code 0x%x\n", login_rsp.status);
            //return _EXIT_SOCKET;
    }
    
    /** not really needed here, since we'll disconnect soon after */
    
    /*status_req.length = sizeof(status_req);
    status_req.type = STATUS_REQ;
    status_req.status = 0;
    AES_set_encrypt_key(randomseed, sizeof(randomseed)*8, &enc_key);
    memcpy(iv, seed, sizeof(iv));
    AES_cbc_encrypt((uint8_t*)&status_req, (uint8_t*)&status_req, sizeof(status_req), &enc_key, iv, AES_ENCRYPT);
    if (verbose) fprintf(stderr, "Sending status\n");
    
    ret = write(sockfd, &status_req, sizeof(status_req));
    if (ret != sizeof(status_req)) {
        fprintf(stderr, "Error sending status, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }*/
    
    return _EXIT_SUCCESS;
}

static int send_standby()
{
    int ret;
    AES_KEY   enc_key;
    AES_KEY   dec_key;
    struct standby_request standby_req;
    struct standby_response standby_rsp;
    
    
    standby_req.length = sizeof(standby_req) - sizeof(standby_req.padding);
    standby_req.type = STANDBY_REQ;
    memset(standby_req.padding, 0, sizeof(standby_req.padding));
    
    AES_set_encrypt_key(randomseed, sizeof(randomseed)*8, &enc_key);
    //memcpy(iv, seed, sizeof(iv));
    AES_cbc_encrypt((uint8_t*)&standby_req, (uint8_t*)&standby_req, sizeof(standby_req), &enc_key, ive, AES_ENCRYPT);
    if (verbose) fprintf(stderr, "Sending standby\n");
    
    ret = write(sockfd, &standby_req, sizeof(standby_req));
    if (ret != sizeof(standby_req)) {
        fprintf(stderr, "Error sending standby, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    ret = read(sockfd, (uint8_t*)&standby_rsp, sizeof(standby_rsp));
    if (ret <=0) {
        fprintf(stderr, "Error reading standby response, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    AES_set_decrypt_key(randomseed, sizeof(randomseed)*8, &dec_key);
    AES_cbc_encrypt((uint8_t*)&standby_rsp, (uint8_t*)&standby_rsp, sizeof(standby_rsp), &dec_key, ivd, AES_DECRYPT);
    
    if(standby_rsp.length != (sizeof(standby_rsp)-sizeof(standby_rsp.padding)))
        fprintf(stderr, "Invalid app start response size %u\n", standby_rsp.length);
    
    if(standby_rsp.type != STANDBY_RSP)
        fprintf(stderr, "Invalid app start response type %x\n", standby_rsp.type);

    if(standby_rsp.status != 0)
        fprintf(stderr, "cannot enter standby, error %u\n", standby_rsp.status);
    else
        fprintf(stderr, "ok\n");

    
    return _EXIT_SUCCESS;
}

static int start_app(const char* app_id)
{
    struct app_request app_req;
    struct app_response app_rsp;
    int ret;
    AES_KEY   enc_key;
    AES_KEY   dec_key;
    
    if (verbose) fprintf(stderr, "Starting %s\n", app_id);
    
    app_req.length = sizeof(app_req)-sizeof(app_req.padding);
    app_req.type = APP_START_REQ;
    strncpy((char*)app_req.app_id, app_id, sizeof(app_req.app_id));
    
    AES_set_encrypt_key(randomseed, sizeof(randomseed)*8, &enc_key);
    //memcpy(iv, seed, sizeof(iv));
    AES_cbc_encrypt((uint8_t*)&app_req, (uint8_t*)&app_req, sizeof(app_req), &enc_key, ive, AES_ENCRYPT);
        
    ret = write(sockfd, &app_req, sizeof(app_req));
    if (ret != sizeof(app_req)) {
        fprintf(stderr, "Error sending app start, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
    
    ret = read(sockfd, (uint8_t*)&app_rsp, sizeof(app_rsp));
    if (ret <=0) {
        fprintf(stderr, "Error reading start app response, %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }
   
    AES_set_decrypt_key(randomseed, sizeof(randomseed)*8, &dec_key);
    AES_cbc_encrypt((uint8_t*)&app_rsp, (uint8_t*)&app_rsp, sizeof(app_rsp), &dec_key, ivd, AES_DECRYPT);
    
    if(app_rsp.length != (sizeof(app_rsp)-sizeof(app_rsp.padding)))
        fprintf(stderr, "Invalid app start response size %u\n", app_rsp.length);
    
    if(app_rsp.type != APP_START_RSP)
        fprintf(stderr, "Invalid app start response type %x\n", app_rsp.type);

    if(app_rsp.status != 0)
        fprintf(stderr, "cannot start app id %s, error %u\n", app_id, app_rsp.status);
    else
        fprintf(stderr, "ok\n");
        
    return _EXIT_SUCCESS;
}

static int probe_device(int probes, int device_state)
{
    ssize_t bytes;
    socklen_t sock_size;
    int i;
    memset(reply, 0, sizeof(struct ddp_reply));
    
    sprintf(pkt_output,
        "SRCH * HTTP/1.1\r\n"
        "device - discovery - protocol - version:%s\r\n\r\n",
        _DDP_VERSION);


    if (verbose) fprintf(stderr, "Scanning");
    
    for (i = 0; i < probes; i++) {
        sa_remote.sin_port = htons(port_remote);
        bytes = sendto(sd, pkt_output, strlen(pkt_output), 0,
            (struct sockaddr *)&sa_remote, sizeof(struct sockaddr_in));
        if (bytes < 0) {
            fprintf(stderr, "Error writing packet: %s\n", strerror(errno));
            return -1;
        }

        sock_size = sizeof(struct sockaddr_in);
        bytes = recvfrom(sd, pkt_input, page_size, 0,
            (struct sockaddr *)&sa_remote, &sock_size);
        if (bytes < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "Error reading packet: %s\n", strerror(errno));
                return -1;
            }
        }
        else {
            if (ddp_parse(pkt_input, reply) != 0) continue;
            
            if(((device_state >= 0) && (device_state == reply->code)) || (device_state < 0))
            {
				if (verbose) fputc('\r', stderr);
				return 1;
			}
			else
				sleep(1);
        }

        if (verbose) fputc('.', stderr);
    }
    if (verbose) fputc('\r', stderr);
    return 0;
}

int main(int argc, char *argv[])
{
    char* app_id = NULL;
    char* passcode = NULL;
    int ret = _EXIT_SUCCESS;
    atexit(onexit);

    page_size = getpagesize();
    long buffer_size = page_size * 3;

    buffer = malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    pkt_input = buffer;
    pkt_output = buffer + page_size;
    json_buffer = buffer + page_size * 2;

    static struct option options[] =
    {
        { "probe", 2, 0, 'P' },
        { "wake", 0, 0, 'W' },
        { "standby", 0, 0, 'S' },
        { "broadcast", 0, 0, 'B' },
        { "local-port", 1, 0, 'L' },
        { "remote-host", 1, 0, 'H' },
        { "remote-port", 1, 0, 'R' },
        { "interface", 1, 0, 'I' },
        { "json", 0, 0, 'j' },
        { "verbose", 0, 0, 'v' },
        { "help", 0, 0, 'h' },
        { "login", 0, 0, 'l' },
        { "start", 1, 0, 's' },
        { "credential", 0, 0, 'c' },
        { "passcode", 0, 0, 'p' },
        { "version", 0, 0, 'V' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1 ;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "PWSBL:H:R:I:jvh?lc:s:Vp:", options, &o)) == -1) break;
        switch (rc) {
        case 'P':
            probe = 1;
            break;
        case 'c':
            cred = strdup(optarg);
            break;
        case 'W':
            wakeup = 1;
            break;
        case 'S':
            standby = 1;
            login = 1; /* must be logged in */
            break;
        case 'l':
            login = 1;
            break;
        case 'B':
            broadcast = 1;
            break;
        case 'L':
            port_local = (short)atoi(optarg);
            break;
        case 'H':
            host_remote = strdup(optarg);
            break;
        case 'R':
            port_remote = (short)atoi(optarg);
            break;
        case 'I':
            iface = strdup(optarg);
            break;
        case 's':
            app_id = strdup(optarg);
            login = 1;
            break;
        case 'p':
            if(strlen(optarg) > 16)
            {
                fprintf(stderr, "Invalid passcode\n");
                return _EXIT_BADOPTION;
            }
            passcode = strdup(optarg);
            break;
        case 'j':
            json = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case '?':
            fprintf(stderr,
                "Try %s --help for more information.\n", argv[0]);
            return _EXIT_BADOPTION;
        case 'V':
            print_version();
            return _EXIT_SUCCESS;
        case 'h':
            usage(0);
            break;
        }
    }

    if (cred == NULL && !probe) {
        fprintf(stderr, "A user credential is required.\n");
        return _EXIT_NOUSERCRED;
    }

    if (!broadcast && host_remote == NULL) {
        fprintf(stderr, "Either broadcast or remote host is required.\n");
        return _EXIT_NOHOSTADDR;
    }

    if (broadcast && host_remote != NULL) {
        fprintf(stderr, "Broadcast and remote host can not both be set.\n");
        return _EXIT_BADHOSTADDR;
    }

    if (!login && passcode != NULL) {
        fprintf(stderr, "passcode must be used with login option\n");
        return _EXIT_BADOPTION;
    }
    //struct sockaddr_in sa_local, sa_remote;

    memset(&sa_local, 0, sizeof(struct sockaddr_in));
    memset(&sa_remote, 0, sizeof(struct sockaddr_in));

    sa_local.sin_family = AF_INET;
    sa_local.sin_port = htons(port_local);

    sa_remote.sin_family = AF_INET;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    if (bind(sd, (struct sockaddr *)&sa_local, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    if (broadcast) {
        sa_remote.sin_addr.s_addr = INADDR_BROADCAST;

        int enable = 1;
        if ((setsockopt(sd,
            SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable))) == -1) {
            fprintf(stderr, "Error enabling broadcasts: %s\n", strerror(errno));
            return _EXIT_SOCKET;
        }
    }
    else {
        struct addrinfo hints, *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = sa_remote.sin_family;

        if ((rc = getaddrinfo(host_remote, NULL, &hints, &result)) != 0) {
            fprintf(stderr, "Error resolving remote address: %s: %s\n",
                host_remote, gai_strerror(rc));
            return _EXIT_HOSTNOTFOUND;
        }

        struct sockaddr_in *sa_in_src =
            (struct sockaddr_in *)result->ai_addr;
        sa_remote.sin_addr.s_addr = sa_in_src->sin_addr.s_addr;
        freeaddrinfo(result);
    }

    if (iface != NULL) {
        if (iface_get_bcast_addr(iface, &sa_remote) != 0)
            return _EXIT_SOCKET;
    }

    struct timeval tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (setsockopt(sd,
        SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1) {
        fprintf(stderr, "Error setting socket read time-out: %s\n", strerror(errno));
        return _EXIT_SOCKET;
    }

    
    reply = malloc(sizeof(struct ddp_reply));
    

    int found_device = 0;

    found_device = probe_device(_PROBES, -1);
    if(found_device < 0)
        return _EXIT_SOCKET;

    if (!found_device) {
        fprintf(stderr, "No device found.\n");
        return _EXIT_DEVNOTFOUND;
    }
    
    fprintf(stderr, "Device found");
    if (verbose) {
        fprintf(stderr, ": %s(%s) [%s/%s]",
            reply->host_name, inet_ntoa(sa_remote.sin_addr), reply->host_type, reply->host_id);
        switch (reply->code) {
        case 200:
           wakeup = 0; /* no need to wakeup */
            if (reply->running_app_name != NULL) {
                fprintf(stderr, ": %s (%s)",
                    reply->running_app_name, reply->running_app_titleid);
            }
            else fprintf(stderr, ": Home Screen");
            break;
        case 620:
            fprintf(stderr, ": Standby");
            break;
        default:
            fprintf(stderr, ": Unknown status (%hd)", reply->code);
            break;
        }
    }
    else fputc('.', stderr);
    fputc('\n', stderr);
    
    if (probe && json) json_output(reply);
    

    if (probe)
        return _EXIT_SUCCESS;
    if(wakeup) {
        ret = ddp_send("WAKEUP");
        if(ret != _EXIT_SUCCESS)
            return ret;
        
    }
    if(login) {
        probe_device(40, 200);
        ret = ddp_send("LAUNCH");
        sleep(1);
        connect_device();
        send_login(passcode);
        sleep(1);
    }
    if(app_id) {
        start_app(app_id);
        sleep(1);
    }
    if(standby) {
        send_standby();
        sleep(1);
    }
    if(sockfd >= 0)
        close(sockfd);
    if(app_id)
        free(app_id);
    if(passcode)
        free(passcode);  
    return ret;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
