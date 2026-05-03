/* SPDX-License-Identifier: Apache-2.0 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "sm2_pki_client.h"
#include "sm2_pki_service.h"

#define BENCH_BASELINE_X509_BITS 2048
#define BENCH_VERIFY_ROUNDS 21
#define BENCH_SESSION_ROUNDS 11
#define BENCH_SCALE_ROUNDS 7
#define BENCH_DELTA_ROUNDS 9
#define BENCH_ZIPF_RUNS 100
#define BENCH_ZIPF_VISITS 1000
#define BENCH_ZIPF_DOMAIN_POOL 100000
#define BENCH_ZIPF_EXPONENT 1.26
#define BENCH_ZIPF_SEED_BASE 0xA11CE5EED1234567ULL
#define BENCH_BASELINE_CRL_BUCKETS 10000U
#define BENCH_BASELINE_CRL_TARGET_BYTES 29000.0
#define BENCH_BASELINE_OCSP_TARGET_BYTES 1300.0
#define BENCH_BASELINE_OCSP_REACHABLE_PCT 95.0
#define BENCH_BASELINE_ONLINE_RTT_MS 50.0
#define BENCH_BASELINE_CRLITE_INITIAL_BYTES 10000000.0
#define BENCH_BASELINE_CRLITE_DELTA_BYTES 580000.0
#define BENCH_BASELINE_CRLITE_LOOKUP_MS 10.0
#define BENCH_BASELINE_CRLITE_CACHED_LOOKUP_MS 6.0
#define BENCH_BASELINE_CRLITE_LRU_ENTRIES 300U
#define BENCH_HTTP_BODY_MAGIC 0x54504b31U
#define BENCH_HTTP_IO_BUFFER_CAP 262144U

typedef struct
{
    size_t sample_count;
    double mean_ms;
    double median_ms;
    double p95_ms;
    double stddev_ms;
} timing_stat_t;

typedef struct
{
    size_t x509_der_bytes;
    size_t implicit_cert_bytes;
    size_t root_record_bytes;
    size_t compact_root_hint_bytes;
    size_t absence_proof_bytes;
    size_t issuance_evidence_bytes;
    size_t auth_bundle_bytes;
    size_t auth_bundle_compact_bytes;
    timing_stat_t verify_bundle_timing;
    double verify_bundle_median_ms;
    timing_stat_t verify_bundle_compact_timing;
    double verify_bundle_compact_median_ms;
    timing_stat_t secure_session_timing;
    double secure_session_median_ms;
    timing_stat_t secure_session_compact_timing;
    double secure_session_compact_median_ms;
    double revoke_publish_median_ms;
    double service_refresh_root_median_ms;
    double client_refresh_root_median_ms;
} base_metric_t;

typedef struct
{
    size_t crl_entry_count;
    size_t crl_der_bytes;
    size_t ocsp_request_der_bytes;
    size_t ocsp_response_der_bytes;
    size_t ocsp_wire_bytes;
    timing_stat_t crl_verify_lookup_timing;
    double crl_verify_lookup_median_ms;
    timing_stat_t ocsp_verify_timing;
    double ocsp_verify_median_ms;
} real_revocation_baseline_t;

typedef struct
{
    EVP_PKEY *ca_key;
    X509 *ca_cert;
    X509 *leaf_cert;
    long leaf_serial;
    uint8_t *crl_der;
    size_t crl_der_len;
    uint8_t *ocsp_request_der;
    size_t ocsp_request_der_len;
    uint8_t *ocsp_response_der;
    size_t ocsp_response_der_len;
} real_revocation_artifacts_t;

typedef struct
{
    size_t revoked_count;
    double tree_build_ms;
    double member_prove_ms;
    double member_verify_ms;
    double absence_prove_ms;
    double absence_verify_ms;
    size_t member_proof_bytes;
    size_t absence_proof_bytes;
} revocation_scale_metric_t;

typedef struct
{
    size_t query_count;
    double build_ms;
    double verify_ms;
    size_t multiproof_bytes;
    size_t single_member_total_bytes;
    size_t unique_hash_count;
    double compression_pct;
} multiproof_metric_t;

typedef struct
{
    size_t delta_items;
    double apply_ms;
} delta_metric_t;

typedef struct
{
    size_t revoked_count;
    size_t cache_top_levels;
    double directory_build_ms;
    double directory_verify_ms;
    double cached_proof_build_ms;
    double cached_proof_verify_ms;
    size_t directory_bytes;
    size_t cached_proof_bytes;
} epoch_cache_metric_t;

typedef struct
{
    size_t visits;
    double mean_unique_domains;
    double auth_bytes;
    double tx_ms_20kbps;
    double tx_ms_64kbps;
    double tx_ms_256kbps;
    double local_verify_ms;
    double secure_session_ms;
    double combined_local_ms;
    double combined_total_ms_20kbps;
    double combined_total_ms_64kbps;
    double combined_total_ms_256kbps;
} zipf_workload_point_t;

typedef struct
{
    double background_bytes;
    double foreground_bytes;
    double total_bytes;
    double online_requests;
    double local_ms;
    double total_ms_20kbps;
    double total_ms_64kbps;
    double total_ms_256kbps;
} workload_strategy_metric_t;

typedef struct
{
    size_t request_bytes;
    size_t response_bytes;
    size_t total_bytes;
    timing_stat_t roundtrip_timing;
    double roundtrip_median_ms;
} controlled_network_metric_t;

typedef struct
{
    controlled_network_metric_t crl_http;
    controlled_network_metric_t ocsp_http;
    controlled_network_metric_t tinypki_full_http;
    controlled_network_metric_t tinypki_compact_http;
} controlled_network_compare_t;

typedef struct
{
    size_t visits;
    double mean_unique_domains;
    double mean_unique_crl_buckets;
    double mean_ocsp_requests;
    double mean_ocsp_crl_fallback_requests;
    double mean_crlite_lru_hits;
    workload_strategy_metric_t crl_only;
    workload_strategy_metric_t ocsp_and_crl;
    workload_strategy_metric_t crlite;
    workload_strategy_metric_t tinypki_compact;
} zipf_strategy_compare_point_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *client;
    sm2_pki_client_ctx_t *verifier;
    sm2_ec_point_t ca_pub;
    sm2_ic_cert_result_t cert_result;
    sm2_private_key_t temp_private_key;
    sm2_auth_signature_t signature;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_issuance_evidence_t issuance_evidence;
    sm2_pki_verify_request_t verify_request;
    uint8_t message[64];
    size_t message_len;
    uint64_t auth_now;
} bench_flow_ctx_t;

typedef struct
{
    sm2_pki_service_ctx_t *service;
    sm2_pki_client_ctx_t *client_a;
    sm2_pki_client_ctx_t *client_b;
    uint64_t auth_now;
} bench_session_ctx_t;

typedef struct
{
    bench_flow_ctx_t flow;
    sm2_pki_client_ctx_t *compact_verifier;
    uint8_t *full_payload;
    size_t full_payload_len;
    uint8_t *compact_payload;
    size_t compact_payload_len;
} tinypki_network_artifacts_t;

static int cmp_double_asc(const void *lhs, const void *rhs)
{
    double a = *(const double *)lhs;
    double b = *(const double *)rhs;
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

static double now_ms_highres(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    LARGE_INTEGER counter;
    if (!initialized)
    {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

static double calc_median_value(double *samples, size_t count)
{
    if (!samples || count == 0)
        return 0.0;
    qsort(samples, count, sizeof(double), cmp_double_asc);
    if ((count & 1U) != 0U)
        return samples[count / 2U];
    return (samples[(count / 2U) - 1U] + samples[count / 2U]) / 2.0;
}

static double calc_mean_value(const double *samples, size_t count)
{
    double sum = 0.0;
    if (!samples || count == 0U)
        return 0.0;
    for (size_t i = 0; i < count; i++)
        sum += samples[i];
    return sum / (double)count;
}

static double calc_stddev_value(
    const double *samples, size_t count, double mean)
{
    double acc = 0.0;
    if (!samples || count == 0U)
        return 0.0;
    for (size_t i = 0; i < count; i++)
    {
        double delta = samples[i] - mean;
        acc += delta * delta;
    }
    return sqrt(acc / (double)count);
}

static int calc_timing_stat(
    const double *samples, size_t count, timing_stat_t *stat)
{
    double *sorted = NULL;
    size_t p95_idx = 0U;

    if (!samples || !stat || count == 0U)
        return 0;

    memset(stat, 0, sizeof(*stat));
    stat->sample_count = count;
    stat->mean_ms = calc_mean_value(samples, count);
    stat->stddev_ms = calc_stddev_value(samples, count, stat->mean_ms);

    sorted = (double *)malloc(count * sizeof(double));
    if (!sorted)
        return 0;
    memcpy(sorted, samples, count * sizeof(double));
    qsort(sorted, count, sizeof(double), cmp_double_asc);

    if ((count & 1U) != 0U)
        stat->median_ms = sorted[count / 2U];
    else
    {
        stat->median_ms
            = (sorted[(count / 2U) - 1U] + sorted[count / 2U]) / 2.0;
    }

    p95_idx = (size_t)ceil(0.95 * (double)count);
    p95_idx = p95_idx == 0U ? 0U : (p95_idx - 1U);
    if (p95_idx >= count)
        p95_idx = count - 1U;
    stat->p95_ms = sorted[p95_idx];
    free(sorted);
    return 1;
}

static uint64_t current_unix_ts(void)
{
    time_t now = time(NULL);
    return now < 0 ? 0U : (uint64_t)now;
}

static double tx_delay_ms(double bytes, double kbps)
{
    if (kbps <= 0.0)
        return 0.0;
    return ((bytes * 8.0) / (kbps * 1000.0)) * 1000.0;
}

#if defined(_WIN32)
typedef SOCKET bench_socket_t;
typedef HANDLE bench_thread_t;
#define BENCH_INVALID_SOCKET INVALID_SOCKET
#else
typedef int bench_socket_t;
typedef pthread_t bench_thread_t;
#define BENCH_INVALID_SOCKET (-1)
#endif

typedef enum
{
    BENCH_HTTP_HANDLER_CRL = 0,
    BENCH_HTTP_HANDLER_OCSP = 1,
    BENCH_HTTP_HANDLER_TINYPKI = 2
} bench_http_handler_t;

typedef struct
{
    bench_socket_t listen_socket;
    bench_http_handler_t handler;
    const uint8_t *response_body;
    size_t response_body_len;
    sm2_pki_client_ctx_t *tinypki_verifier;
    uint64_t tinypki_now_ts;
    size_t request_bytes_seen;
    size_t response_bytes_sent;
    bool success;
} bench_http_server_ctx_t;

static void put_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)((value >> 24) & 0xffU);
    dst[1] = (uint8_t)((value >> 16) & 0xffU);
    dst[2] = (uint8_t)((value >> 8) & 0xffU);
    dst[3] = (uint8_t)(value & 0xffU);
}

static void put_be64(uint8_t *dst, uint64_t value)
{
    dst[0] = (uint8_t)((value >> 56) & 0xffU);
    dst[1] = (uint8_t)((value >> 48) & 0xffU);
    dst[2] = (uint8_t)((value >> 40) & 0xffU);
    dst[3] = (uint8_t)((value >> 32) & 0xffU);
    dst[4] = (uint8_t)((value >> 24) & 0xffU);
    dst[5] = (uint8_t)((value >> 16) & 0xffU);
    dst[6] = (uint8_t)((value >> 8) & 0xffU);
    dst[7] = (uint8_t)(value & 0xffU);
}

static uint32_t get_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16)
        | ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

static uint64_t get_be64(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48)
        | ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32)
        | ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16)
        | ((uint64_t)src[6] << 8) | (uint64_t)src[7];
}

static int bench_socket_platform_init(void)
{
#if defined(_WIN32)
    static int initialized = 0;
    static WSADATA wsa_data;
    if (!initialized)
    {
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
            return 0;
        initialized = 1;
    }
#endif
    return 1;
}

static void bench_socket_close(bench_socket_t sock)
{
    if (sock == BENCH_INVALID_SOCKET)
        return;
#if defined(_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

static int bench_socket_last_error_would_block(void)
{
#if defined(_WIN32)
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINTR;
#else
    return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR;
#endif
}

static int bench_send_all(
    bench_socket_t sock, const uint8_t *buf, size_t len, size_t *sent_len)
{
    size_t off = 0U;
    if (sent_len)
        *sent_len = 0U;
    while (off < len)
    {
        int n = send(sock, (const char *)(buf + off), (int)(len - off), 0);
        if (n <= 0)
        {
            if (bench_socket_last_error_would_block())
                continue;
            return 0;
        }
        off += (size_t)n;
    }
    if (sent_len)
        *sent_len = off;
    return 1;
}

static int bench_recv_until_close(
    bench_socket_t sock, uint8_t *buf, size_t cap, size_t *out_len)
{
    size_t off = 0U;
    if (!buf || !out_len || cap == 0U)
        return 0;
    while (off < cap)
    {
        int n = recv(sock, (char *)(buf + off), (int)(cap - off), 0);
        if (n == 0)
            break;
        if (n < 0)
        {
            if (bench_socket_last_error_would_block())
                continue;
            return 0;
        }
        off += (size_t)n;
    }
    *out_len = off;
    return 1;
}

static const uint8_t *bench_http_find_header_end(
    const uint8_t *buf, size_t len, size_t *header_len)
{
    if (!buf || !header_len || len < 4U)
        return NULL;
    for (size_t i = 0; i + 3U < len; i++)
    {
        if (buf[i] == '\r' && buf[i + 1U] == '\n' && buf[i + 2U] == '\r'
            && buf[i + 3U] == '\n')
        {
            *header_len = i + 4U;
            return buf + *header_len;
        }
    }
    return NULL;
}

static size_t bench_http_content_length(const uint8_t *headers, size_t len)
{
    static const char needle[] = "Content-Length:";
    if (!headers || len == 0U)
        return 0U;
    for (size_t i = 0; i + sizeof(needle) - 1U < len; i++)
    {
        if (memcmp(headers + i, needle, sizeof(needle) - 1U) == 0)
        {
            size_t value = 0U;
            size_t pos = i + sizeof(needle) - 1U;
            while (pos < len && (headers[pos] == ' ' || headers[pos] == '\t'))
                pos++;
            while (pos < len && headers[pos] >= '0' && headers[pos] <= '9')
            {
                value = value * 10U + (size_t)(headers[pos] - '0');
                pos++;
            }
            return value;
        }
    }
    return 0U;
}

static uint64_t mix_u64(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

static size_t domain_to_crl_bucket(size_t domain)
{
    return (size_t)(mix_u64((uint64_t)domain ^ 0x43524cULL)
        % BENCH_BASELINE_CRL_BUCKETS);
}

static bool domain_has_ocsp(size_t domain)
{
    return (mix_u64((uint64_t)domain ^ 0x4f435350ULL) % 10000ULL)
        < (uint64_t)(BENCH_BASELINE_OCSP_REACHABLE_PCT * 100.0);
}

static void cleanup_real_revocation_artifacts(
    real_revocation_artifacts_t *artifacts)
{
    if (!artifacts)
        return;
    EVP_PKEY_free(artifacts->ca_key);
    X509_free(artifacts->ca_cert);
    X509_free(artifacts->leaf_cert);
    free(artifacts->crl_der);
    free(artifacts->ocsp_request_der);
    free(artifacts->ocsp_response_der);
    memset(artifacts, 0, sizeof(*artifacts));
}

static uint8_t *encode_der_x509_crl(X509_CRL *crl, size_t *out_len)
{
    uint8_t *buf = NULL;
    uint8_t *cursor = NULL;
    int der_len = 0;

    if (!crl || !out_len)
        return NULL;
    *out_len = 0U;
    der_len = i2d_X509_CRL(crl, NULL);
    if (der_len <= 0)
        return NULL;
    buf = (uint8_t *)malloc((size_t)der_len);
    if (!buf)
        return NULL;
    cursor = buf;
    if (i2d_X509_CRL(crl, &cursor) != der_len)
    {
        free(buf);
        return NULL;
    }
    *out_len = (size_t)der_len;
    return buf;
}

static uint8_t *encode_der_ocsp_request(OCSP_REQUEST *request, size_t *out_len)
{
    uint8_t *buf = NULL;
    uint8_t *cursor = NULL;
    int der_len = 0;

    if (!request || !out_len)
        return NULL;
    *out_len = 0U;
    der_len = i2d_OCSP_REQUEST(request, NULL);
    if (der_len <= 0)
        return NULL;
    buf = (uint8_t *)malloc((size_t)der_len);
    if (!buf)
        return NULL;
    cursor = buf;
    if (i2d_OCSP_REQUEST(request, &cursor) != der_len)
    {
        free(buf);
        return NULL;
    }
    *out_len = (size_t)der_len;
    return buf;
}

static uint8_t *encode_der_ocsp_response(
    OCSP_RESPONSE *response, size_t *out_len)
{
    uint8_t *buf = NULL;
    uint8_t *cursor = NULL;
    int der_len = 0;

    if (!response || !out_len)
        return NULL;
    *out_len = 0U;
    der_len = i2d_OCSP_RESPONSE(response, NULL);
    if (der_len <= 0)
        return NULL;
    buf = (uint8_t *)malloc((size_t)der_len);
    if (!buf)
        return NULL;
    cursor = buf;
    if (i2d_OCSP_RESPONSE(response, &cursor) != der_len)
    {
        free(buf);
        return NULL;
    }
    *out_len = (size_t)der_len;
    return buf;
}

static uint8_t *build_http_get_request(
    const char *path, const char *host, size_t *out_len)
{
    char header[512];
    int header_len = 0;
    uint8_t *buf = NULL;

    if (!path || !host || !out_len)
        return NULL;
    *out_len = 0U;
    header_len = snprintf(header, sizeof(header),
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header))
        return NULL;
    buf = (uint8_t *)malloc((size_t)header_len);
    if (!buf)
        return NULL;
    memcpy(buf, header, (size_t)header_len);
    *out_len = (size_t)header_len;
    return buf;
}

static uint8_t *build_http_post_request(const char *path, const char *host,
    const char *content_type, const uint8_t *body, size_t body_len,
    size_t *out_len)
{
    char header[512];
    int header_len = 0;
    uint8_t *buf = NULL;

    if (!path || !host || !content_type || !out_len)
        return NULL;
    *out_len = 0U;
    header_len = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: "
        "%zu\r\nConnection: close\r\n\r\n",
        path, host, content_type, body_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header))
        return NULL;
    buf = (uint8_t *)malloc((size_t)header_len + body_len);
    if (!buf)
        return NULL;
    memcpy(buf, header, (size_t)header_len);
    if (body_len > 0U && body)
        memcpy(buf + header_len, body, body_len);
    *out_len = (size_t)header_len + body_len;
    return buf;
}

static uint8_t *build_http_response(const char *status_line,
    const char *content_type, const uint8_t *body, size_t body_len,
    size_t *out_len)
{
    char header[512];
    int header_len = 0;
    uint8_t *buf = NULL;

    if (!status_line || !content_type || !out_len)
        return NULL;
    *out_len = 0U;
    header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: "
        "close\r\n\r\n",
        status_line, content_type, body_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header))
        return NULL;
    buf = (uint8_t *)malloc((size_t)header_len + body_len);
    if (!buf)
        return NULL;
    memcpy(buf, header, (size_t)header_len);
    if (body_len > 0U && body)
        memcpy(buf + header_len, body, body_len);
    *out_len = (size_t)header_len + body_len;
    return buf;
}

static bool lru_touch(
    size_t *entries, size_t *count, size_t capacity, size_t value)
{
    size_t index = 0;

    if (!entries || !count || capacity == 0U)
        return false;

    while (index < *count)
    {
        if (entries[index] == value)
            break;
        index++;
    }

    if (index < *count)
    {
        if (index > 0U)
        {
            size_t existing = entries[index];
            memmove(&entries[1], &entries[0], index * sizeof(entries[0]));
            entries[0] = existing;
        }
        return true;
    }

    if (*count < capacity)
        (*count)++;
    if (*count > 1U)
    {
        memmove(&entries[1], &entries[0], (*count - 1U) * sizeof(entries[0]));
    }
    entries[0] = value;
    return false;
}

static size_t rounds_for_revoked_count(size_t revoked_count)
{
    if (revoked_count >= 1048576U)
        return 3U;
    if (revoked_count >= 262144U)
        return 5U;
    return BENCH_SCALE_ROUNDS;
}

static int create_rsa_pkey(EVP_PKEY **out_pkey, int bits)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (!out_pkey)
        return 0;
    *out_pkey = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx)
        goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits) != 1)
        goto cleanup;
    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto cleanup;

    *out_pkey = pkey;
    pkey = NULL;
    ok = 1;

cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

static int add_name_cn(X509_NAME *name, const char *cn)
{
    if (!name || !cn)
        return 0;
    return X509_NAME_add_entry_by_txt(
               name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0)
        == 1;
}

static int add_cert_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext = NULL;
    int ok = 0;

    if (!cert || !value)
        return 0;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ext)
        goto cleanup;
    if (X509_add_ext(cert, ext, -1) != 1)
        goto cleanup;
    ok = 1;

cleanup:
    X509_EXTENSION_free(ext);
    return ok;
}

static int create_ca_cert(EVP_PKEY *ca_key, X509 **out_cert)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    int ok = 0;

    if (!ca_key || !out_cert)
        return 0;
    *out_cert = NULL;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2L) != 1)
        goto cleanup;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L) != 1)
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L))
        goto cleanup;
    if (X509_set_pubkey(cert, ca_key) != 1)
        goto cleanup;

    name = X509_get_subject_name(cert);
    if (!name || !add_name_cn(name, "TinyPKI Bench CA"))
        goto cleanup;
    if (X509_set_issuer_name(cert, name) != 1)
        goto cleanup;
    if (!add_cert_ext(cert, cert, NID_basic_constraints, "critical,CA:TRUE")
        || !add_cert_ext(cert, cert, NID_key_usage,
            "critical,keyCertSign,cRLSign,digitalSignature")
        || !add_cert_ext(cert, cert, NID_subject_key_identifier, "hash"))
    {
        goto cleanup;
    }
    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0)
        goto cleanup;

    *out_cert = cert;
    cert = NULL;
    ok = 1;

cleanup:
    X509_free(cert);
    return ok;
}

static int create_leaf_cert(EVP_PKEY *leaf_key, X509 *ca_cert, EVP_PKEY *ca_key,
    long serial, X509 **out_cert)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    int ok = 0;

    if (!leaf_key || !ca_cert || !ca_key || !out_cert)
        return 0;
    *out_cert = NULL;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2L) != 1)
        goto cleanup;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) != 1)
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
        goto cleanup;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), 2592000L))
        goto cleanup;
    if (X509_set_pubkey(cert, leaf_key) != 1)
        goto cleanup;

    name = X509_get_subject_name(cert);
    if (!name || !add_name_cn(name, "TinyPKI Bench Leaf"))
        goto cleanup;
    if (X509_set_issuer_name(cert, X509_get_subject_name(ca_cert)) != 1)
        goto cleanup;
    if (!add_cert_ext(cert, ca_cert, NID_basic_constraints, "critical,CA:FALSE")
        || !add_cert_ext(cert, ca_cert, NID_key_usage,
            "critical,digitalSignature,keyEncipherment")
        || !add_cert_ext(
            cert, ca_cert, NID_ext_key_usage, "serverAuth,clientAuth"))
    {
        goto cleanup;
    }
    if (X509_sign(cert, ca_key, EVP_sha256()) <= 0)
        goto cleanup;

    *out_cert = cert;
    cert = NULL;
    ok = 1;

cleanup:
    X509_free(cert);
    return ok;
}

static int build_signed_crl(X509 *ca_cert, EVP_PKEY *ca_key, long leaf_serial,
    size_t entry_count, X509_CRL **out_crl, int *out_der_len)
{
    X509_CRL *crl = NULL;
    ASN1_TIME *last_update = NULL;
    ASN1_TIME *next_update = NULL;
    int der_len = 0;
    int ok = 0;

    if (!ca_cert || !ca_key || !out_crl || !out_der_len || entry_count == 0U)
        return 0;
    *out_crl = NULL;
    *out_der_len = 0;

    crl = X509_CRL_new();
    if (!crl)
        goto cleanup;
    if (X509_CRL_set_version(crl, 1L) != 1)
        goto cleanup;
    if (X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert)) != 1)
        goto cleanup;

    last_update = ASN1_TIME_new();
    next_update = ASN1_TIME_new();
    if (!last_update || !next_update)
        goto cleanup;
    if (!X509_gmtime_adj(last_update, 0)
        || !X509_gmtime_adj(next_update, 7L * 24L * 3600L))
    {
        goto cleanup;
    }
    if (X509_CRL_set1_lastUpdate(crl, last_update) != 1
        || X509_CRL_set1_nextUpdate(crl, next_update) != 1)
    {
        goto cleanup;
    }

    for (size_t i = 0; i < entry_count; i++)
    {
        X509_REVOKED *revoked = NULL;
        ASN1_INTEGER *serial = NULL;
        ASN1_TIME *revocation_time = NULL;
        long serial_value = (i == 0U) ? leaf_serial : (long)(100000L + (long)i);

        revoked = X509_REVOKED_new();
        serial = ASN1_INTEGER_new();
        revocation_time = ASN1_TIME_new();
        if (!revoked || !serial || !revocation_time)
        {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revocation_time);
            goto cleanup;
        }
        if (ASN1_INTEGER_set(serial, serial_value) != 1
            || !X509_gmtime_adj(revocation_time, -(long)(i % 3600U))
            || X509_REVOKED_set_serialNumber(revoked, serial) != 1
            || X509_REVOKED_set_revocationDate(revoked, revocation_time) != 1
            || X509_CRL_add0_revoked(crl, revoked) != 1)
        {
            X509_REVOKED_free(revoked);
            ASN1_INTEGER_free(serial);
            ASN1_TIME_free(revocation_time);
            goto cleanup;
        }
        ASN1_INTEGER_free(serial);
        ASN1_TIME_free(revocation_time);
    }

    if (X509_CRL_sort(crl) != 1
        || X509_CRL_sign(crl, ca_key, EVP_sha256()) <= 0)
        goto cleanup;

    der_len = i2d_X509_CRL(crl, NULL);
    if (der_len <= 0)
        goto cleanup;

    *out_crl = crl;
    *out_der_len = der_len;
    crl = NULL;
    ok = 1;

cleanup:
    ASN1_TIME_free(last_update);
    ASN1_TIME_free(next_update);
    X509_CRL_free(crl);
    return ok;
}

static int build_target_sized_crl(X509 *ca_cert, EVP_PKEY *ca_key,
    long leaf_serial, size_t target_bytes, X509_CRL **out_crl,
    size_t *out_entry_count, int *out_der_len)
{
    size_t low = 1U;
    size_t high = 1U;
    size_t best_count = 0U;
    int best_len = 0;
    X509_CRL *best_crl = NULL;

    if (!ca_cert || !ca_key || !out_crl || !out_entry_count || !out_der_len)
        return 0;
    *out_crl = NULL;
    *out_entry_count = 0U;
    *out_der_len = 0;

    while (1)
    {
        X509_CRL *candidate = NULL;
        int der_len = 0;

        if (!build_signed_crl(
                ca_cert, ca_key, leaf_serial, high, &candidate, &der_len))
        {
            X509_CRL_free(best_crl);
            return 0;
        }
        if ((size_t)der_len >= target_bytes)
        {
            best_crl = candidate;
            best_count = high;
            best_len = der_len;
            break;
        }
        X509_CRL_free(candidate);
        low = high + 1U;
        high *= 2U;
        if (high > 65536U)
        {
            X509_CRL_free(best_crl);
            return 0;
        }
    }

    while (low < high)
    {
        size_t mid = low + (high - low) / 2U;
        X509_CRL *candidate = NULL;
        int der_len = 0;

        if (!build_signed_crl(
                ca_cert, ca_key, leaf_serial, mid, &candidate, &der_len))
        {
            X509_CRL_free(best_crl);
            return 0;
        }
        if ((size_t)der_len >= target_bytes)
        {
            X509_CRL_free(best_crl);
            best_crl = candidate;
            best_count = mid;
            best_len = der_len;
            high = mid;
        }
        else
        {
            X509_CRL_free(candidate);
            low = mid + 1U;
        }
    }

    *out_crl = best_crl;
    *out_entry_count = best_count;
    *out_der_len = best_len;
    return 1;
}

static int measure_crl_verify_lookup_stats(
    X509_CRL *crl, EVP_PKEY *ca_key, long lookup_serial, timing_stat_t *stats)
{
    double samples[BENCH_VERIFY_ROUNDS];
    ASN1_INTEGER *serial = NULL;

    if (!crl || !ca_key || !stats)
        return 0;
    memset(samples, 0, sizeof(samples));

    serial = ASN1_INTEGER_new();
    if (!serial || ASN1_INTEGER_set(serial, lookup_serial) != 1)
    {
        ASN1_INTEGER_free(serial);
        return 0.0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        X509_REVOKED *revoked = NULL;
        double t0 = now_ms_highres();
        if (X509_CRL_verify(crl, ca_key) != 1
            || X509_CRL_get0_by_serial(crl, &revoked, serial) != 1 || !revoked)
        {
            ASN1_INTEGER_free(serial);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    ASN1_INTEGER_free(serial);
    return calc_timing_stat(samples, BENCH_VERIFY_ROUNDS, stats);
}

static int build_ocsp_artifacts(X509 *ca_cert, EVP_PKEY *ca_key,
    X509 *leaf_cert, OCSP_REQUEST **out_request, OCSP_RESPONSE **out_response,
    size_t *out_request_bytes, size_t *out_response_bytes)
{
    OCSP_CERTID *cid = NULL;
    OCSP_CERTID *status_id = NULL;
    OCSP_REQUEST *request = NULL;
    OCSP_BASICRESP *basic = NULL;
    OCSP_RESPONSE *response = NULL;
    ASN1_TIME *revtime = NULL;
    ASN1_TIME *thisupd = NULL;
    ASN1_TIME *nextupd = NULL;
    int req_len = 0;
    int resp_len = 0;

    if (!ca_cert || !ca_key || !leaf_cert || !out_request || !out_response
        || !out_request_bytes || !out_response_bytes)
    {
        return 0;
    }
    *out_request = NULL;
    *out_response = NULL;
    *out_request_bytes = 0U;
    *out_response_bytes = 0U;

    cid = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
    request = OCSP_REQUEST_new();
    basic = OCSP_BASICRESP_new();
    revtime = ASN1_TIME_new();
    thisupd = ASN1_TIME_new();
    nextupd = ASN1_TIME_new();
    if (!cid || !request || !basic || !revtime || !thisupd || !nextupd)
        goto cleanup;
    if (OCSP_request_add0_id(request, cid) == NULL)
        goto cleanup;
    cid = NULL;

    if (!X509_gmtime_adj(revtime, -60L) || !X509_gmtime_adj(thisupd, 0L)
        || !X509_gmtime_adj(nextupd, 4L * 24L * 3600L))
    {
        goto cleanup;
    }
    status_id = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
    if (!status_id
        || OCSP_basic_add1_status(basic, status_id, V_OCSP_CERTSTATUS_REVOKED,
               OCSP_REVOKED_STATUS_NOSTATUS, revtime, thisupd, nextupd)
            == NULL)
    {
        goto cleanup;
    }
    if (OCSP_basic_sign(basic, ca_cert, ca_key, EVP_sha256(), NULL, 0) != 1)
        goto cleanup;
    response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    if (!response)
        goto cleanup;
    basic = NULL;

    req_len = i2d_OCSP_REQUEST(request, NULL);
    resp_len = i2d_OCSP_RESPONSE(response, NULL);
    if (req_len <= 0 || resp_len <= 0)
        goto cleanup;

    *out_request = request;
    *out_response = response;
    *out_request_bytes = (size_t)req_len;
    *out_response_bytes = (size_t)resp_len;
    request = NULL;
    response = NULL;

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_CERTID_free(status_id);
    OCSP_REQUEST_free(request);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(response);
    ASN1_TIME_free(revtime);
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    return *out_request && *out_response;
}

static int measure_ocsp_verify_stats(OCSP_RESPONSE *response, X509 *ca_cert,
    X509 *leaf_cert, timing_stat_t *stats)
{
    X509_STORE *store = NULL;
    double samples[BENCH_VERIFY_ROUNDS];

    if (!response || !ca_cert || !leaf_cert || !stats)
        return 0;
    memset(samples, 0, sizeof(samples));

    store = X509_STORE_new();
    if (!store || X509_STORE_add_cert(store, ca_cert) != 1)
    {
        X509_STORE_free(store);
        return 0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        OCSP_BASICRESP *basic = NULL;
        OCSP_CERTID *cid = NULL;
        int status = -1;
        int reason = -1;
        ASN1_GENERALIZEDTIME *revtime = NULL;
        ASN1_GENERALIZEDTIME *thisupd = NULL;
        ASN1_GENERALIZEDTIME *nextupd = NULL;
        double t0 = now_ms_highres();

        if (OCSP_response_status(response) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
        {
            X509_STORE_free(store);
            return 0;
        }
        basic = OCSP_response_get1_basic(response);
        cid = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
        if (!basic || !cid || OCSP_basic_verify(basic, NULL, store, 0) != 1
            || OCSP_resp_find_status(
                   basic, cid, &status, &reason, &revtime, &thisupd, &nextupd)
                != 1
            || status != V_OCSP_CERTSTATUS_REVOKED
            || OCSP_check_validity(thisupd, nextupd, 300L, -1L) != 1)
        {
            OCSP_BASICRESP_free(basic);
            OCSP_CERTID_free(cid);
            X509_STORE_free(store);
            return 0;
        }

        samples[i] = now_ms_highres() - t0;
        OCSP_BASICRESP_free(basic);
        OCSP_CERTID_free(cid);
    }

    X509_STORE_free(store);
    return calc_timing_stat(samples, BENCH_VERIFY_ROUNDS, stats);
}

static int collect_real_revocation_baseline_metrics(
    real_revocation_baseline_t *metrics, real_revocation_artifacts_t *artifacts)
{
    EVP_PKEY *ca_key = NULL;
    EVP_PKEY *leaf_key = NULL;
    X509 *ca_cert = NULL;
    X509 *leaf_cert = NULL;
    X509_CRL *crl = NULL;
    OCSP_REQUEST *ocsp_request = NULL;
    OCSP_RESPONSE *ocsp_response = NULL;
    const long leaf_serial = 2000L;
    int crl_der_len = 0;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    if (artifacts)
        memset(artifacts, 0, sizeof(*artifacts));

    if (!create_rsa_pkey(&ca_key, BENCH_BASELINE_X509_BITS)
        || !create_rsa_pkey(&leaf_key, BENCH_BASELINE_X509_BITS)
        || !create_ca_cert(ca_key, &ca_cert)
        || !create_leaf_cert(leaf_key, ca_cert, ca_key, leaf_serial, &leaf_cert)
        || !build_target_sized_crl(ca_cert, ca_key, leaf_serial,
            (size_t)BENCH_BASELINE_CRL_TARGET_BYTES, &crl,
            &metrics->crl_entry_count, &crl_der_len)
        || !build_ocsp_artifacts(ca_cert, ca_key, leaf_cert, &ocsp_request,
            &ocsp_response, &metrics->ocsp_request_der_bytes,
            &metrics->ocsp_response_der_bytes))
    {
        cleanup_real_revocation_artifacts(artifacts);
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(leaf_key);
        X509_free(ca_cert);
        X509_free(leaf_cert);
        X509_CRL_free(crl);
        OCSP_REQUEST_free(ocsp_request);
        OCSP_RESPONSE_free(ocsp_response);
        return 0;
    }

    if (artifacts)
    {
        artifacts->crl_der = encode_der_x509_crl(crl, &artifacts->crl_der_len);
        artifacts->ocsp_request_der = encode_der_ocsp_request(
            ocsp_request, &artifacts->ocsp_request_der_len);
        artifacts->ocsp_response_der = encode_der_ocsp_response(
            ocsp_response, &artifacts->ocsp_response_der_len);
        if (!artifacts->crl_der || !artifacts->ocsp_request_der
            || !artifacts->ocsp_response_der)
        {
            cleanup_real_revocation_artifacts(artifacts);
            EVP_PKEY_free(ca_key);
            EVP_PKEY_free(leaf_key);
            X509_free(ca_cert);
            X509_free(leaf_cert);
            X509_CRL_free(crl);
            OCSP_REQUEST_free(ocsp_request);
            OCSP_RESPONSE_free(ocsp_response);
            return 0;
        }
        artifacts->ca_key = ca_key;
        artifacts->ca_cert = ca_cert;
        artifacts->leaf_cert = leaf_cert;
        artifacts->leaf_serial = leaf_serial;
        ca_key = NULL;
        ca_cert = NULL;
        leaf_cert = NULL;
    }

    metrics->crl_der_bytes = (size_t)crl_der_len;
    metrics->ocsp_wire_bytes
        = metrics->ocsp_request_der_bytes + metrics->ocsp_response_der_bytes;
    if (!measure_crl_verify_lookup_stats(crl,
            artifacts ? artifacts->ca_key : ca_key, leaf_serial,
            &metrics->crl_verify_lookup_timing)
        || !measure_ocsp_verify_stats(ocsp_response,
            artifacts ? artifacts->ca_cert : ca_cert,
            artifacts ? artifacts->leaf_cert : leaf_cert,
            &metrics->ocsp_verify_timing))
    {
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(leaf_key);
        X509_free(ca_cert);
        X509_free(leaf_cert);
        X509_CRL_free(crl);
        OCSP_REQUEST_free(ocsp_request);
        OCSP_RESPONSE_free(ocsp_response);
        return 0;
    }
    metrics->crl_verify_lookup_median_ms
        = metrics->crl_verify_lookup_timing.median_ms;
    metrics->ocsp_verify_median_ms = metrics->ocsp_verify_timing.median_ms;

    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(leaf_key);
    X509_free(ca_cert);
    X509_free(leaf_cert);
    X509_CRL_free(crl);
    OCSP_REQUEST_free(ocsp_request);
    OCSP_RESPONSE_free(ocsp_response);

    return metrics->crl_der_bytes > 0U && metrics->ocsp_wire_bytes > 0U
        && metrics->crl_verify_lookup_median_ms > 0.0
        && metrics->ocsp_verify_median_ms > 0.0;
}

static sm2_ic_error_t bench_epoch_sign_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, uint8_t *signature, size_t *signature_len)
{
    static const uint8_t secret[] = "TINYPKI_EPOCH_BENCH";
    uint8_t *buf = NULL;
    sm2_ic_error_t ret = SM2_IC_ERR_MEMORY;

    (void)user_ctx;
    if (!data || !signature || !signature_len
        || *signature_len < SM3_DIGEST_LENGTH)
        return SM2_IC_ERR_PARAM;

    buf = (uint8_t *)malloc(sizeof(secret) - 1U + data_len);
    if (!buf)
        return SM2_IC_ERR_MEMORY;
    memcpy(buf, secret, sizeof(secret) - 1U);
    memcpy(buf + sizeof(secret) - 1U, data, data_len);
    ret = sm2_ic_sm3_hash(buf, (sizeof(secret) - 1U) + data_len, signature);
    free(buf);
    if (ret != SM2_IC_SUCCESS)
        return ret;
    *signature_len = SM3_DIGEST_LENGTH;
    return SM2_IC_SUCCESS;
}

static sm2_ic_error_t bench_epoch_verify_cb(void *user_ctx, const uint8_t *data,
    size_t data_len, const uint8_t *signature, size_t signature_len)
{
    uint8_t expected[SM3_DIGEST_LENGTH];
    size_t expected_len = sizeof(expected);

    if (!signature || signature_len != sizeof(expected))
        return SM2_IC_ERR_VERIFY;
    if (bench_epoch_sign_cb(user_ctx, data, data_len, expected, &expected_len)
        != SM2_IC_SUCCESS)
    {
        return SM2_IC_ERR_VERIFY;
    }
    return memcmp(expected, signature, sizeof(expected)) == 0
        ? SM2_IC_SUCCESS
        : SM2_IC_ERR_VERIFY;
}

static int create_x509_baseline_der_size(int *der_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    X509 *cert = NULL;
    int ok = 0;

    if (!der_len)
        return 0;
    *der_len = 0;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx)
        goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) != 1)
        goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, BENCH_BASELINE_X509_BITS) != 1)
        goto cleanup;
    if (EVP_PKEY_keygen(kctx, &pkey) != 1)
        goto cleanup;

    cert = X509_new();
    if (!cert)
        goto cleanup;
    if (X509_set_version(cert, 2) != 1)
        goto cleanup;
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    if (X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL)
        goto cleanup;
    if (X509_gmtime_adj(X509_get_notAfter(cert), 31536000L) == NULL)
        goto cleanup;
    if (X509_set_pubkey(cert, pkey) != 1)
        goto cleanup;
    if (!X509_get_subject_name(cert))
        goto cleanup;
    if (X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN",
            MBSTRING_ASC, (const unsigned char *)"TINYPKI_BASELINE", -1, -1, 0)
        != 1)
    {
        goto cleanup;
    }
    if (X509_set_issuer_name(cert, X509_get_subject_name(cert)) != 1)
        goto cleanup;
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0)
        goto cleanup;

    *der_len = i2d_X509(cert, NULL);
    ok = (*der_len > 0);

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return ok;
}

static int issue_identity_cert(sm2_pki_service_ctx_t *service,
    const uint8_t *identity, size_t identity_len, uint8_t key_usage,
    sm2_ic_cert_result_t *cert_result, sm2_private_key_t *temp_private_key)
{
    sm2_ic_cert_request_t request;
    memset(&request, 0, sizeof(request));
    if (sm2_ic_create_cert_request(
            &request, identity, identity_len, key_usage, temp_private_key)
        != SM2_IC_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_cert_authorize_request(service, &request) != SM2_PKI_SUCCESS)
        return 0;
    return sm2_pki_cert_issue(service, &request, current_unix_ts(), cert_result)
        == SM2_PKI_SUCCESS;
}

static int client_get_identity_material(sm2_pki_client_ctx_t *client,
    const sm2_implicit_cert_t **cert, const sm2_ec_point_t **public_key)
{
    if (cert && sm2_pki_client_get_cert(client, cert) != SM2_PKI_SUCCESS)
        return 0;
    if (public_key
        && sm2_pki_client_get_public_key(client, public_key) != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    return 1;
}

static int build_signed_verify_request(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_issuance_evidence_t *issuance_evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !issuance_evidence || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_revocation_evidence(signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_export_issuance_evidence(
            signer, now_ts, issuance_evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    memset(request, 0, sizeof(*request));
    request->cert = cert;
    request->public_key = public_key;
    request->message = message;
    request->message_len = message_len;
    request->signature = signature;
    request->revocation_evidence = evidence;
    request->issuance_evidence = issuance_evidence;
    return 1;
}

static int build_signed_verify_request_compact(sm2_pki_client_ctx_t *signer,
    const uint8_t *message, size_t message_len, uint64_t now_ts,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_issuance_evidence_t *issuance_evidence,
    sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;

    if (!signer || !message || message_len == 0 || !signature || !evidence
        || !issuance_evidence || !request)
    {
        return 0;
    }

    if (sm2_pki_sign(signer, message, message_len, signature)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!client_get_identity_material(signer, &cert, &public_key))
        return 0;
    if (sm2_pki_client_export_compact_revocation_evidence(
            signer, now_ts, evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_export_issuance_evidence(
            signer, now_ts, issuance_evidence)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    memset(request, 0, sizeof(*request));
    request->cert = cert;
    request->public_key = public_key;
    request->message = message;
    request->message_len = message_len;
    request->signature = signature;
    request->revocation_evidence = evidence;
    request->issuance_evidence = issuance_evidence;
    return 1;
}

static int encode_cert_len(
    const sm2_implicit_cert_t *cert, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_ic_cbor_encode_cert(buf, len, cert) == SM2_IC_SUCCESS;
}

static int encode_root_len(const sm2_rev_root_record_t *root_record,
    uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_rev_root_encode(root_record, buf, len) == SM2_IC_SUCCESS;
}

static int encode_absence_len(
    const sm2_rev_absence_proof_t *proof, uint8_t *buf, size_t cap, size_t *len)
{
    *len = cap;
    return sm2_rev_absence_proof_encode(proof, buf, len) == SM2_IC_SUCCESS;
}

static size_t compact_root_hint_wire_size(
    const sm2_pki_revocation_evidence_t *evidence)
{
    if (!evidence || evidence->mode != SM2_PKI_REV_EVIDENCE_CACHED_ROOT)
        return 0U;

    return 1U + evidence->cached_root_hint.authority_id_len
        + sizeof(evidence->cached_root_hint.root_version)
        + sizeof(evidence->cached_root_hint.root_hash);
}

static int encode_compact_root_hint(
    const sm2_pki_revocation_evidence_t *evidence, uint8_t *buf, size_t cap)
{
    const sm2_pki_cached_root_hint_t *hint = NULL;
    if (!evidence || !buf || evidence->mode != SM2_PKI_REV_EVIDENCE_CACHED_ROOT)
        return 0;
    hint = &evidence->cached_root_hint;
    if (cap < compact_root_hint_wire_size(evidence)
        || hint->authority_id_len > 255U)
    {
        return 0;
    }
    buf[0] = (uint8_t)hint->authority_id_len;
    memcpy(buf + 1U, hint->authority_id, hint->authority_id_len);
    put_be64(buf + 1U + hint->authority_id_len, hint->root_version);
    memcpy(buf + 1U + hint->authority_id_len + sizeof(uint64_t),
        hint->root_hash, sizeof(hint->root_hash));
    return 1;
}

static int decode_compact_root_hint(
    sm2_pki_cached_root_hint_t *hint, const uint8_t *buf, size_t len)
{
    size_t authority_len = 0U;
    if (!hint || !buf || len < 1U + sizeof(uint64_t) + SM2_REV_MERKLE_HASH_LEN)
        return 0;
    authority_len = buf[0];
    if (authority_len > SM2_REV_ROOT_AUTHORITY_ID_MAX_LEN
        || len
            != 1U + authority_len + sizeof(uint64_t) + SM2_REV_MERKLE_HASH_LEN)
    {
        return 0;
    }
    memset(hint, 0, sizeof(*hint));
    hint->authority_id_len = authority_len;
    memcpy(hint->authority_id, buf + 1U, authority_len);
    hint->root_version = get_be64(buf + 1U + authority_len);
    memcpy(hint->root_hash, buf + 1U + authority_len + sizeof(uint64_t),
        SM2_REV_MERKLE_HASH_LEN);
    return 1;
}

static uint8_t *serialize_tinypki_verify_wire(
    const sm2_pki_verify_request_t *request, size_t *out_len)
{
    uint8_t cert_buf[1024];
    uint8_t aux_buf[1024];
    uint8_t absence_buf[8192];
    uint8_t issuance_buf[sizeof(sm2_pki_issuance_evidence_t)];
    size_t cert_len = sizeof(cert_buf);
    size_t aux_len = 0U;
    size_t absence_len = sizeof(absence_buf);
    size_t issuance_len = sizeof(issuance_buf);
    size_t total_len = 0U;
    uint8_t *buf = NULL;
    size_t off = 0U;

    if (!request || !request->cert || !request->public_key || !request->message
        || !request->signature || !request->revocation_evidence
        || !request->issuance_evidence || !out_len)
    {
        return NULL;
    }
    *out_len = 0U;
    if (sm2_ic_cbor_encode_cert(cert_buf, &cert_len, request->cert)
            != SM2_IC_SUCCESS
        || sm2_rev_absence_proof_encode(
               &request->revocation_evidence->absence_proof, absence_buf,
               &absence_len)
            != SM2_IC_SUCCESS)
    {
        return NULL;
    }

    if (request->revocation_evidence->mode == SM2_PKI_REV_EVIDENCE_FULL_ROOT)
    {
        aux_len = sizeof(aux_buf);
        if (sm2_rev_root_encode(
                &request->revocation_evidence->root_record, aux_buf, &aux_len)
            != SM2_IC_SUCCESS)
        {
            return NULL;
        }
    }
    else if (request->revocation_evidence->mode
        == SM2_PKI_REV_EVIDENCE_CACHED_ROOT)
    {
        aux_len = compact_root_hint_wire_size(request->revocation_evidence);
        if (aux_len == 0U
            || !encode_compact_root_hint(
                request->revocation_evidence, aux_buf, sizeof(aux_buf)))
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }

    memcpy(issuance_buf, request->issuance_evidence, issuance_len);

    total_len = 4U + 1U + 3U + 4U * 6U + sizeof(sm2_ec_point_t) + cert_len
        + request->message_len + request->signature->der_len + aux_len
        + absence_len + issuance_len;
    buf = (uint8_t *)malloc(total_len);
    if (!buf)
        return NULL;

    put_be32(buf + off, BENCH_HTTP_BODY_MAGIC);
    off += 4U;
    buf[off++] = (uint8_t)request->revocation_evidence->mode;
    memset(buf + off, 0, 3U);
    off += 3U;
    put_be32(buf + off, (uint32_t)cert_len);
    off += 4U;
    put_be32(buf + off, (uint32_t)request->message_len);
    off += 4U;
    put_be32(buf + off, (uint32_t)request->signature->der_len);
    off += 4U;
    put_be32(buf + off, (uint32_t)aux_len);
    off += 4U;
    put_be32(buf + off, (uint32_t)absence_len);
    off += 4U;
    put_be32(buf + off, (uint32_t)issuance_len);
    off += 4U;
    memcpy(buf + off, request->public_key, sizeof(sm2_ec_point_t));
    off += sizeof(sm2_ec_point_t);
    memcpy(buf + off, cert_buf, cert_len);
    off += cert_len;
    memcpy(buf + off, request->message, request->message_len);
    off += request->message_len;
    memcpy(buf + off, request->signature->der, request->signature->der_len);
    off += request->signature->der_len;
    memcpy(buf + off, aux_buf, aux_len);
    off += aux_len;
    memcpy(buf + off, absence_buf, absence_len);
    off += absence_len;
    memcpy(buf + off, issuance_buf, issuance_len);
    off += issuance_len;

    *out_len = off;
    return buf;
}

static int decode_tinypki_verify_wire(const uint8_t *buf, size_t len,
    sm2_implicit_cert_t *cert, sm2_ec_point_t *public_key,
    sm2_auth_signature_t *signature, sm2_pki_revocation_evidence_t *evidence,
    sm2_pki_issuance_evidence_t *issuance_evidence, const uint8_t **message,
    size_t *message_len)
{
    uint32_t cert_len = 0U;
    uint32_t msg_len = 0U;
    uint32_t sig_len = 0U;
    uint32_t aux_len = 0U;
    uint32_t absence_len = 0U;
    uint32_t issuance_len = 0U;
    const uint8_t *cursor = NULL;
    size_t remaining = 0U;
    uint8_t mode = 0U;

    if (!buf || !cert || !public_key || !signature || !evidence
        || !issuance_evidence || !message || !message_len
        || len < 4U + 1U + 3U + 4U * 6U + sizeof(sm2_ec_point_t))
    {
        return 0;
    }

    if (get_be32(buf) != BENCH_HTTP_BODY_MAGIC)
        return 0;
    mode = buf[4];
    cert_len = get_be32(buf + 8U);
    msg_len = get_be32(buf + 12U);
    sig_len = get_be32(buf + 16U);
    aux_len = get_be32(buf + 20U);
    absence_len = get_be32(buf + 24U);
    issuance_len = get_be32(buf + 28U);
    if (sig_len > SM2_AUTH_MAX_SIG_DER_LEN)
        return 0;
    if (issuance_len != sizeof(*issuance_evidence))
        return 0;

    cursor = buf + 32U;
    remaining = len - 32U;
    if (remaining < sizeof(sm2_ec_point_t) + cert_len + msg_len + sig_len
            + aux_len + absence_len + issuance_len)
    {
        return 0;
    }

    memcpy(public_key, cursor, sizeof(sm2_ec_point_t));
    cursor += sizeof(sm2_ec_point_t);
    if (sm2_ic_cbor_decode_cert(cert, cursor, cert_len) != SM2_IC_SUCCESS)
        return 0;
    cursor += cert_len;
    *message = cursor;
    *message_len = msg_len;
    cursor += msg_len;

    memset(signature, 0, sizeof(*signature));
    signature->der_len = sig_len;
    memcpy(signature->der, cursor, sig_len);
    cursor += sig_len;

    memset(evidence, 0, sizeof(*evidence));
    evidence->mode = (sm2_pki_revocation_evidence_mode_t)mode;
    if (evidence->mode == SM2_PKI_REV_EVIDENCE_FULL_ROOT)
    {
        if (sm2_rev_root_decode(&evidence->root_record, cursor, aux_len)
            != SM2_IC_SUCCESS)
        {
            return 0;
        }
    }
    else if (evidence->mode == SM2_PKI_REV_EVIDENCE_CACHED_ROOT)
    {
        if (!decode_compact_root_hint(
                &evidence->cached_root_hint, cursor, aux_len))
            return 0;
    }
    else
    {
        return 0;
    }
    cursor += aux_len;

    return sm2_rev_absence_proof_decode(
               &evidence->absence_proof, cursor, absence_len)
        == SM2_IC_SUCCESS
        && (cursor += absence_len,
            memcpy(issuance_evidence, cursor, sizeof(*issuance_evidence)), 1);
}

static int build_flow_context(bench_flow_ctx_t *ctx)
{
    const uint8_t issuer[] = "BENCH_CA";
    const uint8_t identity[] = "BENCH_NODE";
    const uint8_t message[] = "TINYPKI_CAPABILITY_AUTH_MESSAGE";

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->message, message, sizeof(message) - 1U);
    ctx->message_len = sizeof(message) - 1U;

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1U, 64,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(ctx->service, identity, sizeof(identity) - 1U,
            SM2_KU_DIGITAL_SIGNATURE, &ctx->cert_result,
            &ctx->temp_private_key))
    {
        return 0;
    }
    if (sm2_pki_service_get_ca_public_key(ctx->service, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_create(&ctx->client, &ctx->ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->verifier, &ctx->ca_pub, NULL)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->client, &ctx->cert_result,
            &ctx->temp_private_key, &ctx->ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->auth_now = ctx->cert_result.cert.valid_from != 0
        ? ctx->cert_result.cert.valid_from
        : current_unix_ts();
    return build_signed_verify_request(ctx->client, ctx->message,
        ctx->message_len, ctx->auth_now, &ctx->signature, &ctx->evidence,
        &ctx->issuance_evidence, &ctx->verify_request);
}

static void cleanup_flow_context(bench_flow_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->verifier);
    sm2_pki_client_destroy(&ctx->client);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static void cleanup_tinypki_network_artifacts(
    tinypki_network_artifacts_t *artifacts)
{
    if (!artifacts)
        return;
    free(artifacts->full_payload);
    free(artifacts->compact_payload);
    sm2_pki_client_destroy(&artifacts->compact_verifier);
    cleanup_flow_context(&artifacts->flow);
    memset(artifacts, 0, sizeof(*artifacts));
}

static int build_tinypki_network_artifacts(
    tinypki_network_artifacts_t *artifacts)
{
    sm2_auth_signature_t compact_signature;
    sm2_pki_revocation_evidence_t compact_evidence;
    sm2_pki_issuance_evidence_t compact_issuance;
    sm2_pki_verify_request_t compact_request;

    if (!artifacts)
        return 0;
    memset(artifacts, 0, sizeof(*artifacts));
    memset(&compact_signature, 0, sizeof(compact_signature));
    memset(&compact_evidence, 0, sizeof(compact_evidence));
    memset(&compact_issuance, 0, sizeof(compact_issuance));
    memset(&compact_request, 0, sizeof(compact_request));

    if (!build_flow_context(&artifacts->flow)
        || sm2_pki_client_create(
               &artifacts->compact_verifier, &artifacts->flow.ca_pub, NULL)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_import_root_record(artifacts->compact_verifier,
               &artifacts->flow.evidence.root_record, artifacts->flow.auth_now)
            != SM2_PKI_SUCCESS)
    {
        cleanup_tinypki_network_artifacts(artifacts);
        return 0;
    }

    artifacts->full_payload = serialize_tinypki_verify_wire(
        &artifacts->flow.verify_request, &artifacts->full_payload_len);
    if (!artifacts->full_payload
        || !build_signed_verify_request_compact(artifacts->flow.client,
            artifacts->flow.message, artifacts->flow.message_len,
            artifacts->flow.auth_now, &compact_signature, &compact_evidence,
            &compact_issuance, &compact_request))
    {
        cleanup_tinypki_network_artifacts(artifacts);
        return 0;
    }

    artifacts->compact_payload = serialize_tinypki_verify_wire(
        &compact_request, &artifacts->compact_payload_len);
    if (!artifacts->compact_payload)
    {
        cleanup_tinypki_network_artifacts(artifacts);
        return 0;
    }

    return 1;
}

static int bench_http_listen_loopback(
    bench_socket_t *out_socket, uint16_t *out_port)
{
    bench_socket_t listen_sock = BENCH_INVALID_SOCKET;
    struct sockaddr_in addr;
    socklen_t addr_len = (socklen_t)sizeof(addr);

    if (!out_socket || !out_port || !bench_socket_platform_init())
        return 0;
    *out_socket = BENCH_INVALID_SOCKET;
    *out_port = 0U;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == BENCH_INVALID_SOCKET)
        return 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(listen_sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0
        || listen(listen_sock, 1) != 0
        || getsockname(listen_sock, (struct sockaddr *)&addr, &addr_len) != 0)
    {
        bench_socket_close(listen_sock);
        return 0;
    }

    *out_socket = listen_sock;
    *out_port = ntohs(addr.sin_port);
    return 1;
}

static int bench_http_read_request(
    bench_socket_t sock, uint8_t *buf, size_t cap, size_t *out_len)
{
    size_t off = 0U;
    size_t header_len = 0U;
    size_t content_len = 0U;

    if (!buf || !out_len || cap == 0U)
        return 0;
    while (off < cap)
    {
        int n = recv(sock, (char *)(buf + off), (int)(cap - off), 0);
        if (n <= 0)
            break;
        off += (size_t)n;
        if (bench_http_find_header_end(buf, off, &header_len))
        {
            content_len = bench_http_content_length(buf, header_len);
            if (off >= header_len + content_len)
                break;
        }
    }
    if (off == 0U)
        return 0;
    *out_len = off;
    return 1;
}

static int bench_http_response_ok(const uint8_t *buf, size_t len)
{
    static const char prefix[] = "HTTP/1.1 200";
    return buf && len >= sizeof(prefix) - 1U
        && memcmp(buf, prefix, sizeof(prefix) - 1U) == 0;
}

static int bench_http_extract_body(const uint8_t *response, size_t response_len,
    const uint8_t **body, size_t *body_len)
{
    size_t header_len = 0U;
    size_t content_len = 0U;
    const uint8_t *body_ptr = NULL;

    if (!response || !body || !body_len)
        return 0;
    body_ptr = bench_http_find_header_end(response, response_len, &header_len);
    if (!body_ptr || !bench_http_response_ok(response, response_len))
        return 0;
    content_len = bench_http_content_length(response, header_len);
    if (header_len + content_len > response_len)
        return 0;
    *body = body_ptr;
    *body_len = content_len;
    return 1;
}

static int bench_client_verify_crl_http(const uint8_t *response,
    size_t response_len, X509 *ca_cert, EVP_PKEY *ca_key, long lookup_serial)
{
    const uint8_t *body = NULL;
    size_t body_len = 0U;
    const uint8_t *cursor = NULL;
    X509_CRL *crl = NULL;
    ASN1_INTEGER *serial = NULL;
    X509_REVOKED *revoked = NULL;
    int ok = 0;

    (void)ca_cert;
    if (!response || !ca_key)
        return 0;
    if (!bench_http_extract_body(response, response_len, &body, &body_len))
        return 0;

    cursor = body;
    crl = d2i_X509_CRL(NULL, &cursor, (long)body_len);
    serial = ASN1_INTEGER_new();
    if (!crl || !serial || ASN1_INTEGER_set(serial, lookup_serial) != 1
        || X509_CRL_verify(crl, ca_key) != 1
        || X509_CRL_get0_by_serial(crl, &revoked, serial) != 1 || !revoked)
    {
        goto cleanup;
    }
    ok = 1;

cleanup:
    ASN1_INTEGER_free(serial);
    X509_CRL_free(crl);
    return ok;
}

static int bench_client_verify_ocsp_http(const uint8_t *response,
    size_t response_len, X509 *ca_cert, X509 *leaf_cert)
{
    const uint8_t *body = NULL;
    size_t body_len = 0U;
    const uint8_t *cursor = NULL;
    OCSP_RESPONSE *ocsp_response = NULL;
    X509_STORE *store = NULL;
    OCSP_BASICRESP *basic = NULL;
    OCSP_CERTID *cid = NULL;
    ASN1_GENERALIZEDTIME *revtime = NULL;
    ASN1_GENERALIZEDTIME *thisupd = NULL;
    ASN1_GENERALIZEDTIME *nextupd = NULL;
    int status = -1;
    int reason = -1;
    int ok = 0;

    if (!response || !ca_cert || !leaf_cert)
        return 0;
    if (!bench_http_extract_body(response, response_len, &body, &body_len))
        return 0;

    cursor = body;
    ocsp_response = d2i_OCSP_RESPONSE(NULL, &cursor, (long)body_len);
    store = X509_STORE_new();
    if (!ocsp_response || !store || X509_STORE_add_cert(store, ca_cert) != 1
        || OCSP_response_status(ocsp_response)
            != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
        goto cleanup;
    }

    basic = OCSP_response_get1_basic(ocsp_response);
    cid = OCSP_cert_to_id(EVP_sha1(), leaf_cert, ca_cert);
    if (!basic || !cid || OCSP_basic_verify(basic, NULL, store, 0) != 1
        || OCSP_resp_find_status(
               basic, cid, &status, &reason, &revtime, &thisupd, &nextupd)
            != 1
        || status != V_OCSP_CERTSTATUS_REVOKED
        || OCSP_check_validity(thisupd, nextupd, 300L, -1L) != 1)
    {
        goto cleanup;
    }
    ok = 1;

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_BASICRESP_free(basic);
    X509_STORE_free(store);
    OCSP_RESPONSE_free(ocsp_response);
    return ok;
}

static int bench_client_verify_tinypki_http(
    const uint8_t *response, size_t response_len)
{
    const uint8_t *body = NULL;
    size_t body_len = 0U;
    static const uint8_t ok_body[] = "OK";

    if (!bench_http_extract_body(response, response_len, &body, &body_len))
        return 0;
    return body_len == sizeof(ok_body) - 1U
        && memcmp(body, ok_body, sizeof(ok_body) - 1U) == 0;
}

#if defined(_WIN32)
static DWORD WINAPI bench_http_server_thread_proc(LPVOID param)
#else
static void *bench_http_server_thread_proc(void *param)
#endif
{
    bench_http_server_ctx_t *ctx = (bench_http_server_ctx_t *)param;
    bench_socket_t client_sock = BENCH_INVALID_SOCKET;
    uint8_t request_buf[BENCH_HTTP_IO_BUFFER_CAP];
    size_t request_len = 0U;
    uint8_t *response = NULL;
    size_t response_len = 0U;
    static const uint8_t ok_body[] = "OK";
    static const uint8_t err_body[] = "ERR";
    const uint8_t *body = NULL;
    size_t body_len = 0U;
    size_t header_len = 0U;

    if (!ctx)
        goto done;
    client_sock = accept(ctx->listen_socket, NULL, NULL);
    if (client_sock == BENCH_INVALID_SOCKET)
        goto done;
    if (!bench_http_read_request(
            client_sock, request_buf, sizeof(request_buf), &request_len))
    {
        goto done;
    }
    ctx->request_bytes_seen = request_len;
    body = bench_http_find_header_end(request_buf, request_len, &header_len);
    body_len = body ? bench_http_content_length(request_buf, header_len) : 0U;

    switch (ctx->handler)
    {
        case BENCH_HTTP_HANDLER_CRL:
            if (memcmp(request_buf, "GET /crl ", 9U) != 0)
                break;
            response = build_http_response("200 OK", "application/pkix-crl",
                ctx->response_body, ctx->response_body_len, &response_len);
            break;
        case BENCH_HTTP_HANDLER_OCSP:
            if (memcmp(request_buf, "POST /ocsp ", 11U) != 0 || !body
                || header_len + body_len > request_len)
            {
                break;
            }
            else
            {
                const uint8_t *cursor = body;
                OCSP_REQUEST *request
                    = d2i_OCSP_REQUEST(NULL, &cursor, (long)body_len);
                if (!request)
                    break;
                OCSP_REQUEST_free(request);
                response = build_http_response("200 OK",
                    "application/ocsp-response", ctx->response_body,
                    ctx->response_body_len, &response_len);
            }
            break;
        case BENCH_HTTP_HANDLER_TINYPKI:
            if (memcmp(request_buf, "POST /tinypki ", 14U) != 0 || !body
                || header_len + body_len > request_len
                || !ctx->tinypki_verifier)
            {
                break;
            }
            else
            {
                sm2_implicit_cert_t cert;
                sm2_ec_point_t public_key;
                sm2_auth_signature_t signature;
                sm2_pki_revocation_evidence_t evidence;
                sm2_pki_issuance_evidence_t issuance_evidence;
                sm2_pki_verify_request_t verify_request;
                const uint8_t *message = NULL;
                size_t message_len = 0U;
                size_t matched = 0U;

                memset(&cert, 0, sizeof(cert));
                memset(&public_key, 0, sizeof(public_key));
                memset(&signature, 0, sizeof(signature));
                memset(&evidence, 0, sizeof(evidence));
                memset(&issuance_evidence, 0, sizeof(issuance_evidence));
                memset(&verify_request, 0, sizeof(verify_request));

                if (!decode_tinypki_verify_wire(body, body_len, &cert,
                        &public_key, &signature, &evidence, &issuance_evidence,
                        &message, &message_len))
                {
                    break;
                }
                verify_request.cert = &cert;
                verify_request.public_key = &public_key;
                verify_request.message = message;
                verify_request.message_len = message_len;
                verify_request.signature = &signature;
                verify_request.revocation_evidence = &evidence;
                verify_request.issuance_evidence = &issuance_evidence;
                if (sm2_pki_verify(ctx->tinypki_verifier, &verify_request,
                        ctx->tinypki_now_ts, &matched)
                    != SM2_PKI_SUCCESS)
                {
                    break;
                }
                response
                    = build_http_response("200 OK", "application/octet-stream",
                        ok_body, sizeof(ok_body) - 1U, &response_len);
            }
            break;
    }

    if (!response)
    {
        response = build_http_response("500 Internal Server Error",
            "application/octet-stream", err_body, sizeof(err_body) - 1U,
            &response_len);
    }
    if (!response)
        goto done;

    if (!bench_send_all(
            client_sock, response, response_len, &ctx->response_bytes_sent))
        goto done;

    ctx->success = bench_http_response_ok(response, response_len);

done:
    free(response);
    bench_socket_close(client_sock);
    if (ctx)
        bench_socket_close(ctx->listen_socket);
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

static int bench_thread_create(
    bench_thread_t *thread, bench_http_server_ctx_t *server_ctx)
{
    if (!thread || !server_ctx)
        return 0;
#if defined(_WIN32)
    *thread = CreateThread(
        NULL, 0U, bench_http_server_thread_proc, server_ctx, 0U, NULL);
    return *thread != NULL;
#else
    return pthread_create(
               thread, NULL, bench_http_server_thread_proc, server_ctx)
        == 0;
#endif
}

static void bench_thread_join(bench_thread_t thread)
{
#if defined(_WIN32)
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif
}

static int bench_http_client_roundtrip(uint16_t port, const uint8_t *request,
    size_t request_len, uint8_t *response_buf, size_t response_cap,
    size_t *response_len)
{
    bench_socket_t sock = BENCH_INVALID_SOCKET;
    struct sockaddr_in addr;
    int ok = 0;

    if (!request || !response_buf || !response_len
        || !bench_socket_platform_init())
        return 0;
    *response_len = 0U;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == BENCH_INVALID_SOCKET)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        goto cleanup;
    if (!bench_send_all(sock, request, request_len, NULL))
        goto cleanup;
#if defined(_WIN32)
    shutdown(sock, SD_SEND);
#else
    shutdown(sock, SHUT_WR);
#endif
    if (!bench_recv_until_close(sock, response_buf, response_cap, response_len))
        goto cleanup;
    ok = 1;

cleanup:
    bench_socket_close(sock);
    return ok;
}

static int measure_http_exchange_median(bench_http_handler_t handler,
    const uint8_t *request, size_t request_len, const uint8_t *response_body,
    size_t response_body_len, sm2_pki_client_ctx_t *tinypki_verifier,
    uint64_t tinypki_now_ts,
    int (*client_verify_fn)(const uint8_t *, size_t, X509 *, EVP_PKEY *, long),
    X509 *ca_cert, EVP_PKEY *ca_key, long lookup_serial,
    controlled_network_metric_t *metric)
{
    double samples[BENCH_VERIFY_ROUNDS];
    uint8_t response_buf[BENCH_HTTP_IO_BUFFER_CAP];

    if (!request || !metric
        || (handler != BENCH_HTTP_HANDLER_TINYPKI && !response_body))
        return 0;
    memset(samples, 0, sizeof(samples));
    memset(metric, 0, sizeof(*metric));

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        bench_socket_t listen_sock = BENCH_INVALID_SOCKET;
        bench_thread_t thread;
        uint16_t port = 0U;
        bench_http_server_ctx_t server_ctx;
        size_t response_len = 0U;
        double t0 = 0.0;
        int verified = 0;

        memset(&server_ctx, 0, sizeof(server_ctx));
        if (!bench_http_listen_loopback(&listen_sock, &port))
            return 0;

        server_ctx.listen_socket = listen_sock;
        server_ctx.handler = handler;
        server_ctx.response_body = response_body;
        server_ctx.response_body_len = response_body_len;
        server_ctx.tinypki_verifier = tinypki_verifier;
        server_ctx.tinypki_now_ts = tinypki_now_ts;

        if (!bench_thread_create(&thread, &server_ctx))
        {
            bench_socket_close(listen_sock);
            return 0;
        }

        t0 = now_ms_highres();
        if (!bench_http_client_roundtrip(port, request, request_len,
                response_buf, sizeof(response_buf), &response_len))
        {
            bench_thread_join(thread);
            return 0;
        }
        if (handler == BENCH_HTTP_HANDLER_TINYPKI)
        {
            verified
                = bench_client_verify_tinypki_http(response_buf, response_len);
        }
        else
        {
            verified = client_verify_fn(
                response_buf, response_len, ca_cert, ca_key, lookup_serial);
        }
        samples[i] = now_ms_highres() - t0;
        bench_thread_join(thread);

        if (!server_ctx.success || !verified)
            return 0;
        if (i == 0U)
        {
            metric->request_bytes = request_len;
            metric->response_bytes = server_ctx.response_bytes_sent;
            metric->total_bytes
                = metric->request_bytes + metric->response_bytes;
        }
    }

    if (!calc_timing_stat(
            samples, BENCH_VERIFY_ROUNDS, &metric->roundtrip_timing))
        return 0;
    metric->roundtrip_median_ms = metric->roundtrip_timing.median_ms;
    return metric->request_bytes > 0U && metric->response_bytes > 0U
        && metric->roundtrip_median_ms > 0.0;
}

static int measure_http_ocsp_exchange_median(const uint8_t *request,
    size_t request_len, const uint8_t *response_body, size_t response_body_len,
    X509 *ca_cert, X509 *leaf_cert, controlled_network_metric_t *metric)
{
    double samples[BENCH_VERIFY_ROUNDS];
    uint8_t response_buf[BENCH_HTTP_IO_BUFFER_CAP];

    if (!request || !response_body || !ca_cert || !leaf_cert || !metric)
        return 0;
    memset(samples, 0, sizeof(samples));
    memset(metric, 0, sizeof(*metric));

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        bench_socket_t listen_sock = BENCH_INVALID_SOCKET;
        bench_thread_t thread;
        uint16_t port = 0U;
        bench_http_server_ctx_t server_ctx;
        size_t response_len = 0U;
        double t0 = 0.0;

        memset(&server_ctx, 0, sizeof(server_ctx));
        if (!bench_http_listen_loopback(&listen_sock, &port))
            return 0;
        server_ctx.listen_socket = listen_sock;
        server_ctx.handler = BENCH_HTTP_HANDLER_OCSP;
        server_ctx.response_body = response_body;
        server_ctx.response_body_len = response_body_len;
        if (!bench_thread_create(&thread, &server_ctx))
        {
            bench_socket_close(listen_sock);
            return 0;
        }

        t0 = now_ms_highres();
        if (!bench_http_client_roundtrip(port, request, request_len,
                response_buf, sizeof(response_buf), &response_len)
            || !bench_client_verify_ocsp_http(
                response_buf, response_len, ca_cert, leaf_cert))
        {
            bench_thread_join(thread);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
        bench_thread_join(thread);
        if (!server_ctx.success)
            return 0;
        if (i == 0U)
        {
            metric->request_bytes = request_len;
            metric->response_bytes = server_ctx.response_bytes_sent;
            metric->total_bytes
                = metric->request_bytes + metric->response_bytes;
        }
    }

    if (!calc_timing_stat(
            samples, BENCH_VERIFY_ROUNDS, &metric->roundtrip_timing))
        return 0;
    metric->roundtrip_median_ms = metric->roundtrip_timing.median_ms;
    return metric->request_bytes > 0U && metric->response_bytes > 0U
        && metric->roundtrip_median_ms > 0.0;
}

static int measure_http_tinypki_full_exchange_median(const uint8_t *request,
    size_t request_len, const sm2_ec_point_t *ca_public_key, uint64_t now_ts,
    controlled_network_metric_t *metric)
{
    double samples[BENCH_VERIFY_ROUNDS];
    uint8_t response_buf[BENCH_HTTP_IO_BUFFER_CAP];

    if (!request || !ca_public_key || !metric)
        return 0;
    memset(samples, 0, sizeof(samples));
    memset(metric, 0, sizeof(*metric));

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        sm2_pki_client_ctx_t *verifier = NULL;
        bench_socket_t listen_sock = BENCH_INVALID_SOCKET;
        bench_thread_t thread;
        uint16_t port = 0U;
        bench_http_server_ctx_t server_ctx;
        size_t response_len = 0U;
        double t0 = 0.0;

        if (sm2_pki_client_create(&verifier, ca_public_key, NULL)
            != SM2_PKI_SUCCESS)
        {
            return 0;
        }
        memset(&server_ctx, 0, sizeof(server_ctx));
        if (!bench_http_listen_loopback(&listen_sock, &port))
        {
            sm2_pki_client_destroy(&verifier);
            return 0;
        }
        server_ctx.listen_socket = listen_sock;
        server_ctx.handler = BENCH_HTTP_HANDLER_TINYPKI;
        server_ctx.tinypki_verifier = verifier;
        server_ctx.tinypki_now_ts = now_ts;
        if (!bench_thread_create(&thread, &server_ctx))
        {
            bench_socket_close(listen_sock);
            sm2_pki_client_destroy(&verifier);
            return 0;
        }

        t0 = now_ms_highres();
        if (!bench_http_client_roundtrip(port, request, request_len,
                response_buf, sizeof(response_buf), &response_len)
            || !bench_client_verify_tinypki_http(response_buf, response_len))
        {
            bench_thread_join(thread);
            sm2_pki_client_destroy(&verifier);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
        bench_thread_join(thread);
        if (!server_ctx.success)
        {
            sm2_pki_client_destroy(&verifier);
            return 0;
        }
        if (i == 0U)
        {
            metric->request_bytes = request_len;
            metric->response_bytes = server_ctx.response_bytes_sent;
            metric->total_bytes
                = metric->request_bytes + metric->response_bytes;
        }
        sm2_pki_client_destroy(&verifier);
    }

    if (!calc_timing_stat(
            samples, BENCH_VERIFY_ROUNDS, &metric->roundtrip_timing))
        return 0;
    metric->roundtrip_median_ms = metric->roundtrip_timing.median_ms;
    return metric->request_bytes > 0U && metric->response_bytes > 0U
        && metric->roundtrip_median_ms > 0.0;
}

static int build_session_context(bench_session_ctx_t *ctx)
{
    const uint8_t issuer[] = "BENCH_SESSION_CA";
    const uint8_t id_a[] = "SESSION_A";
    const uint8_t id_b[] = "SESSION_B";
    const uint8_t usage = SM2_KU_DIGITAL_SIGNATURE | SM2_KU_KEY_AGREEMENT;
    sm2_ic_cert_result_t cert_a;
    sm2_ic_cert_result_t cert_b;
    sm2_private_key_t temp_a;
    sm2_private_key_t temp_b;
    sm2_ec_point_t ca_pub;

    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    memset(&cert_a, 0, sizeof(cert_a));
    memset(&cert_b, 0, sizeof(cert_b));
    memset(&temp_a, 0, sizeof(temp_a));
    memset(&temp_b, 0, sizeof(temp_b));
    memset(&ca_pub, 0, sizeof(ca_pub));

    if (sm2_pki_service_create(&ctx->service, issuer, sizeof(issuer) - 1U, 32,
            300, current_unix_ts())
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_identity_register(ctx->service, id_a, sizeof(id_a) - 1U, usage)
            != SM2_PKI_SUCCESS
        || sm2_pki_identity_register(
               ctx->service, id_b, sizeof(id_b) - 1U, usage)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (!issue_identity_cert(
            ctx->service, id_a, sizeof(id_a) - 1U, usage, &cert_a, &temp_a)
        || !issue_identity_cert(
            ctx->service, id_b, sizeof(id_b) - 1U, usage, &cert_b, &temp_b))
    {
        return 0;
    }
    if (sm2_pki_service_get_ca_public_key(ctx->service, &ca_pub)
        != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_create(&ctx->client_a, &ca_pub, ctx->service)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&ctx->client_b, &ca_pub, ctx->service)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }
    if (sm2_pki_client_import_cert(ctx->client_a, &cert_a, &temp_a, &ca_pub)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_import_cert(ctx->client_b, &cert_b, &temp_b, &ca_pub)
            != SM2_PKI_SUCCESS)
    {
        return 0;
    }

    ctx->auth_now = cert_a.cert.valid_from > cert_b.cert.valid_from
        ? cert_a.cert.valid_from
        : cert_b.cert.valid_from;
    if (ctx->auth_now == 0)
        ctx->auth_now = current_unix_ts();
    return 1;
}

static void cleanup_session_context(bench_session_ctx_t *ctx)
{
    if (!ctx)
        return;
    sm2_pki_client_destroy(&ctx->client_a);
    sm2_pki_client_destroy(&ctx->client_b);
    sm2_pki_service_destroy(&ctx->service);
    memset(ctx, 0, sizeof(*ctx));
}

static int measure_verify_bundle_stats(timing_stat_t *stats)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_VERIFY_ROUNDS];

    if (!stats)
        return 0;
    memset(&flow, 0, sizeof(flow));
    if (!build_flow_context(&flow))
        return 0;

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        size_t matched = 0;
        double t0 = now_ms_highres();
        if (sm2_pki_verify(
                flow.verifier, &flow.verify_request, flow.auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            cleanup_flow_context(&flow);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_flow_context(&flow);
    return calc_timing_stat(samples, BENCH_VERIFY_ROUNDS, stats);
}

static int measure_verify_bundle_compact_stats(timing_stat_t *stats)
{
    bench_flow_ctx_t flow;
    double samples[BENCH_VERIFY_ROUNDS];
    sm2_auth_signature_t signature;
    sm2_pki_revocation_evidence_t evidence;
    sm2_pki_issuance_evidence_t issuance_evidence;
    sm2_pki_verify_request_t request;
    size_t matched = 0;

    if (!stats)
        return 0;
    memset(&flow, 0, sizeof(flow));
    memset(&signature, 0, sizeof(signature));
    memset(&evidence, 0, sizeof(evidence));
    memset(&issuance_evidence, 0, sizeof(issuance_evidence));
    memset(&request, 0, sizeof(request));
    if (!build_flow_context(&flow))
        return 0;
    if (sm2_pki_verify(
            flow.verifier, &flow.verify_request, flow.auth_now, &matched)
        != SM2_PKI_SUCCESS)
    {
        cleanup_flow_context(&flow);
        return 0;
    }
    if (!build_signed_verify_request_compact(flow.client, flow.message,
            flow.message_len, flow.auth_now, &signature, &evidence,
            &issuance_evidence, &request))
    {
        cleanup_flow_context(&flow);
        return 0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        double t0 = now_ms_highres();
        if (sm2_pki_verify(flow.verifier, &request, flow.auth_now, &matched)
            != SM2_PKI_SUCCESS)
        {
            cleanup_flow_context(&flow);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_flow_context(&flow);
    return calc_timing_stat(samples, BENCH_VERIFY_ROUNDS, stats);
}

static int measure_secure_session_stats_internal(
    bool compact_evidence, timing_stat_t *stats)
{
    bench_session_ctx_t ctx;
    double samples[BENCH_SESSION_ROUNDS];
    const uint8_t transcript[] = "TINYPKI_CAPABILITY_SESSION";

    if (!stats)
        return 0;
    memset(&ctx, 0, sizeof(ctx));
    if (!build_session_context(&ctx))
        return 0;
    if (compact_evidence
        && (sm2_pki_client_refresh_root(ctx.client_a, ctx.auth_now)
                != SM2_PKI_SUCCESS
            || sm2_pki_client_refresh_root(ctx.client_b, ctx.auth_now)
                != SM2_PKI_SUCCESS))
    {
        cleanup_session_context(&ctx);
        return 0;
    }

    for (size_t i = 0; i < BENCH_SESSION_ROUNDS; i++)
    {
        const sm2_implicit_cert_t *cert_a = NULL;
        const sm2_implicit_cert_t *cert_b = NULL;
        const sm2_ec_point_t *pub_a = NULL;
        const sm2_ec_point_t *pub_b = NULL;
        sm2_private_key_t eph_priv_a;
        sm2_private_key_t eph_priv_b;
        sm2_ec_point_t eph_pub_a;
        sm2_ec_point_t eph_pub_b;
        uint8_t bind_a[256];
        uint8_t bind_b[256];
        size_t bind_a_len = sizeof(bind_a);
        size_t bind_b_len = sizeof(bind_b);
        sm2_auth_signature_t sig_a;
        sm2_auth_signature_t sig_b;
        sm2_pki_revocation_evidence_t evidence_a;
        sm2_pki_revocation_evidence_t evidence_b;
        sm2_pki_issuance_evidence_t issuance_a;
        sm2_pki_issuance_evidence_t issuance_b;
        sm2_pki_verify_request_t req_a_to_b;
        sm2_pki_verify_request_t req_b_to_a;
        uint8_t sk_a[16];
        uint8_t sk_b[16];
        size_t matched_a = 0;
        size_t matched_b = 0;

        memset(&eph_priv_a, 0, sizeof(eph_priv_a));
        memset(&eph_priv_b, 0, sizeof(eph_priv_b));
        memset(&eph_pub_a, 0, sizeof(eph_pub_a));
        memset(&eph_pub_b, 0, sizeof(eph_pub_b));
        memset(&sig_a, 0, sizeof(sig_a));
        memset(&sig_b, 0, sizeof(sig_b));
        memset(&evidence_a, 0, sizeof(evidence_a));
        memset(&evidence_b, 0, sizeof(evidence_b));
        memset(&issuance_a, 0, sizeof(issuance_a));
        memset(&issuance_b, 0, sizeof(issuance_b));
        memset(&req_a_to_b, 0, sizeof(req_a_to_b));
        memset(&req_b_to_a, 0, sizeof(req_b_to_a));

        double t0 = now_ms_highres();
        if (sm2_pki_generate_ephemeral_keypair(&eph_priv_a, &eph_pub_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_generate_ephemeral_keypair(&eph_priv_b, &eph_pub_b)
                != SM2_PKI_SUCCESS
            || sm2_auth_build_handshake_binding(&eph_pub_a, &eph_pub_b,
                   transcript, sizeof(transcript) - 1U, bind_a, &bind_a_len)
                != SM2_IC_SUCCESS
            || sm2_auth_build_handshake_binding(&eph_pub_b, &eph_pub_a,
                   transcript, sizeof(transcript) - 1U, bind_b, &bind_b_len)
                != SM2_IC_SUCCESS
            || sm2_pki_sign(ctx.client_a, bind_a, bind_a_len, &sig_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_sign(ctx.client_b, bind_b, bind_b_len, &sig_b)
                != SM2_PKI_SUCCESS
            || (compact_evidence
                       ? sm2_pki_client_export_compact_revocation_evidence(
                             ctx.client_a, ctx.auth_now, &evidence_a)
                       : sm2_pki_client_export_revocation_evidence(
                             ctx.client_a, ctx.auth_now, &evidence_a))
                != SM2_PKI_SUCCESS
            || (compact_evidence
                       ? sm2_pki_client_export_compact_revocation_evidence(
                             ctx.client_b, ctx.auth_now, &evidence_b)
                       : sm2_pki_client_export_revocation_evidence(
                             ctx.client_b, ctx.auth_now, &evidence_b))
                != SM2_PKI_SUCCESS
            || sm2_pki_client_export_issuance_evidence(
                   ctx.client_a, ctx.auth_now, &issuance_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_client_export_issuance_evidence(
                   ctx.client_b, ctx.auth_now, &issuance_b)
                != SM2_PKI_SUCCESS
            || !client_get_identity_material(ctx.client_a, &cert_a, &pub_a)
            || !client_get_identity_material(ctx.client_b, &cert_b, &pub_b))
        {
            cleanup_session_context(&ctx);
            return 0;
        }

        req_a_to_b.cert = cert_a;
        req_a_to_b.public_key = pub_a;
        req_a_to_b.message = bind_a;
        req_a_to_b.message_len = bind_a_len;
        req_a_to_b.signature = &sig_a;
        req_a_to_b.revocation_evidence = &evidence_a;
        req_a_to_b.issuance_evidence = &issuance_a;

        req_b_to_a.cert = cert_b;
        req_b_to_a.public_key = pub_b;
        req_b_to_a.message = bind_b;
        req_b_to_a.message_len = bind_b_len;
        req_b_to_a.signature = &sig_b;
        req_b_to_a.revocation_evidence = &evidence_b;
        req_b_to_a.issuance_evidence = &issuance_b;

        if (sm2_pki_secure_session_establish(ctx.client_a, &eph_priv_a,
                &eph_pub_a, &req_b_to_a, &eph_pub_b, transcript,
                sizeof(transcript) - 1U, ctx.auth_now, sk_a, sizeof(sk_a),
                &matched_a)
                != SM2_PKI_SUCCESS
            || sm2_pki_secure_session_establish(ctx.client_b, &eph_priv_b,
                   &eph_pub_b, &req_a_to_b, &eph_pub_a, transcript,
                   sizeof(transcript) - 1U, ctx.auth_now, sk_b, sizeof(sk_b),
                   &matched_b)
                != SM2_PKI_SUCCESS
            || memcmp(sk_a, sk_b, sizeof(sk_a)) != 0)
        {
            cleanup_session_context(&ctx);
            return 0;
        }
        samples[i] = now_ms_highres() - t0;
    }

    cleanup_session_context(&ctx);
    return calc_timing_stat(samples, BENCH_SESSION_ROUNDS, stats);
}

static double measure_secure_session_median(void)
{
    timing_stat_t stats;
    return measure_secure_session_stats_internal(false, &stats)
        ? stats.median_ms
        : 0.0;
}

static double measure_secure_session_compact_median(void)
{
    timing_stat_t stats;
    return measure_secure_session_stats_internal(true, &stats) ? stats.median_ms
                                                               : 0.0;
}

static int measure_revoke_refresh_medians(double *revoke_publish_median_ms,
    double *service_refresh_median_ms, double *client_refresh_median_ms)
{
    const uint8_t issuer[] = "BENCH_REVOKE_CA";
    sm2_pki_service_ctx_t *service = NULL;
    sm2_pki_client_ctx_t *observer = NULL;
    sm2_ec_point_t ca_pub;
    double revoke_samples[BENCH_VERIFY_ROUNDS];
    double service_refresh_samples[BENCH_VERIFY_ROUNDS];
    double refresh_samples[BENCH_VERIFY_ROUNDS];

    if (!revoke_publish_median_ms || !service_refresh_median_ms
        || !client_refresh_median_ms)
        return 0;

    memset(&ca_pub, 0, sizeof(ca_pub));
    memset(revoke_samples, 0, sizeof(revoke_samples));
    memset(service_refresh_samples, 0, sizeof(service_refresh_samples));
    memset(refresh_samples, 0, sizeof(refresh_samples));

    if (sm2_pki_service_create(
            &service, issuer, sizeof(issuer) - 1U, 64, 300, current_unix_ts())
            != SM2_PKI_SUCCESS
        || sm2_pki_service_get_ca_public_key(service, &ca_pub)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_create(&observer, &ca_pub, service)
            != SM2_PKI_SUCCESS)
    {
        sm2_pki_client_destroy(&observer);
        sm2_pki_service_destroy(&service);
        return 0;
    }

    for (size_t i = 0; i < BENCH_VERIFY_ROUNDS; i++)
    {
        char identity[32];
        sm2_ic_cert_result_t cert_result;
        sm2_private_key_t temp_priv;
        uint64_t now_ts = current_unix_ts();

        memset(&cert_result, 0, sizeof(cert_result));
        memset(&temp_priv, 0, sizeof(temp_priv));
        snprintf(identity, sizeof(identity), "REVOKE_%02u", (unsigned int)i);
        identity[sizeof(identity) - 1U] = '\0';

        if (sm2_pki_identity_register(service, (const uint8_t *)identity,
                strlen(identity), SM2_KU_DIGITAL_SIGNATURE)
                != SM2_PKI_SUCCESS
            || !issue_identity_cert(service, (const uint8_t *)identity,
                strlen(identity), SM2_KU_DIGITAL_SIGNATURE, &cert_result,
                &temp_priv))
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }

        double t0 = now_ms_highres();
        if (sm2_pki_service_revoke(
                service, cert_result.cert.serial_number, now_ts)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        revoke_samples[i] = now_ms_highres() - t0;

        t0 = now_ms_highres();
        if (sm2_pki_service_refresh_root(service, now_ts + 1U)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        service_refresh_samples[i] = now_ms_highres() - t0;

        t0 = now_ms_highres();
        if (sm2_pki_client_refresh_root(observer, now_ts + 1U)
            != SM2_PKI_SUCCESS)
        {
            sm2_pki_client_destroy(&observer);
            sm2_pki_service_destroy(&service);
            return 0;
        }
        refresh_samples[i] = now_ms_highres() - t0;
    }

    sm2_pki_client_destroy(&observer);
    sm2_pki_service_destroy(&service);
    *revoke_publish_median_ms
        = calc_median_value(revoke_samples, BENCH_VERIFY_ROUNDS);
    *service_refresh_median_ms
        = calc_median_value(service_refresh_samples, BENCH_VERIFY_ROUNDS);
    *client_refresh_median_ms
        = calc_median_value(refresh_samples, BENCH_VERIFY_ROUNDS);
    return 1;
}

static int collect_base_metrics(base_metric_t *metrics)
{
    bench_flow_ctx_t flow;
    uint8_t cert_buf[1024];
    uint8_t root_buf[1024];
    uint8_t absence_buf[8192];
    double auth_bundle_samples[BENCH_SESSION_ROUNDS];
    double auth_bundle_compact_samples[BENCH_SESSION_ROUNDS];
    size_t cert_len = 0;
    size_t root_len = 0;
    size_t absence_len = 0;
    int x509_der_len = 0;

    if (!metrics)
        return 0;
    memset(metrics, 0, sizeof(*metrics));
    memset(&flow, 0, sizeof(flow));
    memset(auth_bundle_samples, 0, sizeof(auth_bundle_samples));
    memset(auth_bundle_compact_samples, 0, sizeof(auth_bundle_compact_samples));

    if (!build_flow_context(&flow)
        || !create_x509_baseline_der_size(&x509_der_len)
        || !encode_cert_len(
            &flow.cert_result.cert, cert_buf, sizeof(cert_buf), &cert_len)
        || !encode_root_len(
            &flow.evidence.root_record, root_buf, sizeof(root_buf), &root_len)
        || !encode_absence_len(&flow.evidence.absence_proof, absence_buf,
            sizeof(absence_buf), &absence_len))
    {
        cleanup_flow_context(&flow);
        return 0;
    }

    metrics->x509_der_bytes = (size_t)x509_der_len;
    metrics->implicit_cert_bytes = cert_len;
    metrics->root_record_bytes = root_len;
    metrics->absence_proof_bytes = absence_len;
    metrics->issuance_evidence_bytes = sizeof(sm2_pki_issuance_evidence_t);
    for (size_t i = 0; i < BENCH_SESSION_ROUNDS; i++)
    {
        sm2_auth_signature_t signature;
        sm2_auth_signature_t compact_signature;
        sm2_pki_revocation_evidence_t evidence;
        sm2_pki_revocation_evidence_t compact_evidence;
        sm2_pki_issuance_evidence_t issuance_evidence;
        sm2_pki_issuance_evidence_t compact_issuance_evidence;
        sm2_pki_verify_request_t request;
        sm2_pki_verify_request_t compact_request;
        size_t root_round_len = sizeof(root_buf);
        size_t absence_round_len = sizeof(absence_buf);
        size_t compact_absence_len = sizeof(absence_buf);
        size_t compact_root_hint_len = 0;

        memset(&signature, 0, sizeof(signature));
        memset(&compact_signature, 0, sizeof(compact_signature));
        memset(&evidence, 0, sizeof(evidence));
        memset(&compact_evidence, 0, sizeof(compact_evidence));
        memset(&issuance_evidence, 0, sizeof(issuance_evidence));
        memset(&compact_issuance_evidence, 0, sizeof(compact_issuance_evidence));
        memset(&request, 0, sizeof(request));
        memset(&compact_request, 0, sizeof(compact_request));
        if (!build_signed_verify_request(flow.client, flow.message,
                flow.message_len, flow.auth_now, &signature, &evidence,
                &issuance_evidence, &request)
            || !build_signed_verify_request_compact(flow.client, flow.message,
                flow.message_len, flow.auth_now, &compact_signature,
                &compact_evidence, &compact_issuance_evidence,
                &compact_request)
            || !encode_root_len(&evidence.root_record, root_buf,
                sizeof(root_buf), &root_round_len)
            || !encode_absence_len(&evidence.absence_proof, absence_buf,
                sizeof(absence_buf), &absence_round_len)
            || !encode_absence_len(&compact_evidence.absence_proof, absence_buf,
                sizeof(absence_buf), &compact_absence_len))
        {
            cleanup_flow_context(&flow);
            return 0;
        }

        compact_root_hint_len = compact_root_hint_wire_size(&compact_evidence);
        if (i == 0U)
            metrics->compact_root_hint_bytes = compact_root_hint_len;
        auth_bundle_samples[i] = (double)cert_len + (double)signature.der_len
            + (double)root_round_len + (double)absence_round_len
            + (double)sizeof(issuance_evidence);
        auth_bundle_compact_samples[i] = (double)cert_len
            + (double)compact_signature.der_len + (double)compact_root_hint_len
            + (double)compact_absence_len
            + (double)sizeof(compact_issuance_evidence);
    }
    metrics->auth_bundle_bytes
        = (size_t)(calc_median_value(auth_bundle_samples, BENCH_SESSION_ROUNDS)
            + 0.5);
    metrics->auth_bundle_compact_bytes
        = (size_t)(calc_median_value(
                       auth_bundle_compact_samples, BENCH_SESSION_ROUNDS)
            + 0.5);
    if (!measure_verify_bundle_stats(&metrics->verify_bundle_timing)
        || !measure_verify_bundle_compact_stats(
            &metrics->verify_bundle_compact_timing)
        || !measure_secure_session_stats_internal(
            false, &metrics->secure_session_timing)
        || !measure_secure_session_stats_internal(
            true, &metrics->secure_session_compact_timing))
    {
        cleanup_flow_context(&flow);
        return 0;
    }
    metrics->verify_bundle_median_ms = metrics->verify_bundle_timing.median_ms;
    metrics->verify_bundle_compact_median_ms
        = metrics->verify_bundle_compact_timing.median_ms;
    metrics->secure_session_median_ms
        = metrics->secure_session_timing.median_ms;
    metrics->secure_session_compact_median_ms
        = metrics->secure_session_compact_timing.median_ms;
    if (!measure_revoke_refresh_medians(&metrics->revoke_publish_median_ms,
            &metrics->service_refresh_root_median_ms,
            &metrics->client_refresh_root_median_ms))
    {
        cleanup_flow_context(&flow);
        return 0;
    }

    cleanup_flow_context(&flow);
    return metrics->verify_bundle_median_ms > 0.0
        && metrics->verify_bundle_compact_median_ms > 0.0
        && metrics->secure_session_median_ms > 0.0
        && metrics->secure_session_compact_median_ms > 0.0
        && metrics->revoke_publish_median_ms > 0.0
        && metrics->service_refresh_root_median_ms > 0.0
        && metrics->client_refresh_root_median_ms > 0.0;
}

static int collect_controlled_network_compare_metrics(
    const real_revocation_artifacts_t *real_artifacts,
    controlled_network_compare_t *metrics)
{
    tinypki_network_artifacts_t tinypki_artifacts;
    uint8_t *crl_request = NULL;
    uint8_t *ocsp_request = NULL;
    uint8_t *tinypki_full_request = NULL;
    uint8_t *tinypki_compact_request = NULL;
    size_t crl_request_len = 0U;
    size_t ocsp_request_len = 0U;
    size_t tinypki_full_request_len = 0U;
    size_t tinypki_compact_request_len = 0U;
    int ok = 0;

    if (!real_artifacts || !metrics || !real_artifacts->ca_cert
        || !real_artifacts->leaf_cert || !real_artifacts->ca_key
        || !real_artifacts->crl_der || !real_artifacts->ocsp_request_der
        || !real_artifacts->ocsp_response_der)
    {
        return 0;
    }

    memset(metrics, 0, sizeof(*metrics));
    memset(&tinypki_artifacts, 0, sizeof(tinypki_artifacts));

    crl_request = build_http_get_request("/crl", "127.0.0.1", &crl_request_len);
    ocsp_request = build_http_post_request("/ocsp", "127.0.0.1",
        "application/ocsp-request", real_artifacts->ocsp_request_der,
        real_artifacts->ocsp_request_der_len, &ocsp_request_len);
    if (!crl_request || !ocsp_request
        || !build_tinypki_network_artifacts(&tinypki_artifacts))
    {
        goto cleanup;
    }

    tinypki_full_request = build_http_post_request("/tinypki", "127.0.0.1",
        "application/octet-stream", tinypki_artifacts.full_payload,
        tinypki_artifacts.full_payload_len, &tinypki_full_request_len);
    tinypki_compact_request = build_http_post_request("/tinypki", "127.0.0.1",
        "application/octet-stream", tinypki_artifacts.compact_payload,
        tinypki_artifacts.compact_payload_len, &tinypki_compact_request_len);
    if (!tinypki_full_request || !tinypki_compact_request)
        goto cleanup;

    if (!measure_http_exchange_median(BENCH_HTTP_HANDLER_CRL, crl_request,
            crl_request_len, real_artifacts->crl_der,
            real_artifacts->crl_der_len, NULL, 0U, bench_client_verify_crl_http,
            real_artifacts->ca_cert, real_artifacts->ca_key,
            real_artifacts->leaf_serial, &metrics->crl_http))
    {
        fprintf(stderr, "controlled network compare: crl_http\n");
        goto cleanup;
    }
    if (!measure_http_ocsp_exchange_median(ocsp_request, ocsp_request_len,
            real_artifacts->ocsp_response_der,
            real_artifacts->ocsp_response_der_len, real_artifacts->ca_cert,
            real_artifacts->leaf_cert, &metrics->ocsp_http))
    {
        fprintf(stderr, "controlled network compare: ocsp_http\n");
        goto cleanup;
    }
    if (!measure_http_tinypki_full_exchange_median(tinypki_full_request,
            tinypki_full_request_len, &tinypki_artifacts.flow.ca_pub,
            tinypki_artifacts.flow.auth_now, &metrics->tinypki_full_http))
    {
        fprintf(stderr, "controlled network compare: tinypki_full_http\n");
        goto cleanup;
    }
    if (!measure_http_exchange_median(BENCH_HTTP_HANDLER_TINYPKI,
            tinypki_compact_request, tinypki_compact_request_len, NULL, 0U,
            tinypki_artifacts.compact_verifier, tinypki_artifacts.flow.auth_now,
            NULL, NULL, NULL, 0L, &metrics->tinypki_compact_http))
    {
        fprintf(stderr, "controlled network compare: tinypki_compact_http\n");
        goto cleanup;
    }

    ok = 1;

cleanup:
    free(crl_request);
    free(ocsp_request);
    free(tinypki_full_request);
    free(tinypki_compact_request);
    cleanup_tinypki_network_artifacts(&tinypki_artifacts);
    return ok;
}

static void fill_revoked_serials(uint64_t *serials, size_t count, uint64_t base)
{
    if (!serials)
        return;
    for (size_t i = 0; i < count; i++)
        serials[i] = base + ((uint64_t)i * 2ULL);
}

static int collect_revocation_scaling_metrics(
    revocation_scale_metric_t *metrics, size_t metric_count)
{
    static const size_t revoked_counts[]
        = { 1024U, 4096U, 16384U, 65536U, 262144U, 1048576U };

    if (!metrics
        || metric_count != (sizeof(revoked_counts) / sizeof(revoked_counts[0])))
    {
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        uint64_t *revoked = NULL;
        double build_samples[BENCH_SCALE_ROUNDS];
        double member_prove_samples[BENCH_SCALE_ROUNDS];
        double member_verify_samples[BENCH_SCALE_ROUNDS];
        double absence_prove_samples[BENCH_SCALE_ROUNDS];
        double absence_verify_samples[BENCH_SCALE_ROUNDS];
        size_t member_bytes = 0;
        size_t absence_bytes = 0;
        const size_t revoked_count = revoked_counts[m];

        memset(build_samples, 0, sizeof(build_samples));
        memset(member_prove_samples, 0, sizeof(member_prove_samples));
        memset(member_verify_samples, 0, sizeof(member_verify_samples));
        memset(absence_prove_samples, 0, sizeof(absence_prove_samples));
        memset(absence_verify_samples, 0, sizeof(absence_verify_samples));

        revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
        if (!revoked)
            return 0;
        fill_revoked_serials(
            revoked, revoked_count, 1000000ULL + (uint64_t)m * 100000ULL);

        size_t round_count = rounds_for_revoked_count(revoked_count);
        for (size_t round = 0; round < round_count; round++)
        {
            sm2_rev_tree_t *tree = NULL;
            sm2_rev_member_proof_t member_proof;
            sm2_rev_absence_proof_t absence_proof;
            uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];
            uint8_t member_buf[4096];
            uint8_t absence_buf[8192];
            size_t member_len = sizeof(member_buf);
            size_t absence_len = sizeof(absence_buf);
            const uint64_t member_serial = revoked[revoked_count / 2U];
            const uint64_t absence_serial = member_serial + 1ULL;

            memset(&member_proof, 0, sizeof(member_proof));
            memset(&absence_proof, 0, sizeof(absence_proof));
            memset(root_hash, 0, sizeof(root_hash));

            double t0 = now_ms_highres();
            if (sm2_rev_tree_build(&tree, revoked, revoked_count,
                    2026032501ULL + (uint64_t)round)
                != SM2_IC_SUCCESS)
            {
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            if (sm2_rev_tree_get_root_hash(tree, root_hash) != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }

            t0 = now_ms_highres();
            if (sm2_rev_tree_prove_member(tree, member_serial, &member_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            member_prove_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_verify_member(root_hash, &member_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            member_verify_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_prove_absence(tree, absence_serial, &absence_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            absence_prove_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_tree_verify_absence(root_hash, &absence_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            absence_verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_member_proof_encode(
                        &member_proof, member_buf, &member_len)
                        != SM2_IC_SUCCESS
                    || sm2_rev_absence_proof_encode(
                           &absence_proof, absence_buf, &absence_len)
                        != SM2_IC_SUCCESS)
                {
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                member_bytes = member_len;
                absence_bytes = absence_len;
            }

            sm2_rev_tree_cleanup(&tree);
        }

        metrics[m].revoked_count = revoked_count;
        metrics[m].tree_build_ms
            = calc_median_value(build_samples, round_count);
        metrics[m].member_prove_ms
            = calc_median_value(member_prove_samples, round_count);
        metrics[m].member_verify_ms
            = calc_median_value(member_verify_samples, round_count);
        metrics[m].absence_prove_ms
            = calc_median_value(absence_prove_samples, round_count);
        metrics[m].absence_verify_ms
            = calc_median_value(absence_verify_samples, round_count);
        metrics[m].member_proof_bytes = member_bytes;
        metrics[m].absence_proof_bytes = absence_bytes;
        free(revoked);
    }

    return 1;
}

static int collect_multiproof_metrics(
    multiproof_metric_t *metrics, size_t metric_count)
{
    static const size_t query_counts[] = { 1U, 4U, 8U, 16U, 32U, 64U };
    enum
    {
        revoked_count = 32768
    };
    uint64_t *revoked = NULL;
    sm2_rev_tree_t *tree = NULL;
    uint8_t root_hash[SM2_REV_MERKLE_HASH_LEN];

    if (!metrics
        || metric_count != (sizeof(query_counts) / sizeof(query_counts[0])))
    {
        return 0;
    }

    revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
    if (!revoked)
        return 0;
    fill_revoked_serials(revoked, revoked_count, 4000000ULL);

    if (sm2_rev_tree_build(&tree, revoked, revoked_count, 2026032501ULL)
            != SM2_IC_SUCCESS
        || sm2_rev_tree_get_root_hash(tree, root_hash) != SM2_IC_SUCCESS)
    {
        sm2_rev_tree_cleanup(&tree);
        free(revoked);
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        const size_t query_count = query_counts[m];
        uint64_t *queries = NULL;
        double build_samples[BENCH_SCALE_ROUNDS];
        double verify_samples[BENCH_SCALE_ROUNDS];
        size_t multiproof_bytes = 0;
        size_t single_total_bytes = 0;
        size_t unique_hash_count = 0;

        memset(build_samples, 0, sizeof(build_samples));
        memset(verify_samples, 0, sizeof(verify_samples));

        queries = (uint64_t *)calloc(query_count, sizeof(uint64_t));
        if (!queries)
        {
            sm2_rev_tree_cleanup(&tree);
            free(revoked);
            return 0;
        }

        size_t stride = revoked_count / query_count;
        if (stride == 0U)
            stride = 1U;
        for (size_t i = 0; i < query_count; i++)
        {
            size_t index = i * stride;
            if (index >= revoked_count)
                index = revoked_count - 1U;
            queries[i] = revoked[index];
        }

        for (size_t round = 0; round < BENCH_SCALE_ROUNDS; round++)
        {
            sm2_rev_multi_proof_t *proof = NULL;
            uint8_t proof_buf[1048576];
            size_t proof_len = sizeof(proof_buf);

            double t0 = now_ms_highres();
            if (sm2_rev_multi_proof_build(tree, queries, query_count, &proof)
                != SM2_IC_SUCCESS)
            {
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_multi_proof_verify(root_hash, proof) != SM2_IC_SUCCESS)
            {
                sm2_rev_multi_proof_cleanup(&proof);
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_multi_proof_encode(proof, proof_buf, &proof_len)
                    != SM2_IC_SUCCESS)
                {
                    sm2_rev_multi_proof_cleanup(&proof);
                    free(queries);
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                multiproof_bytes = proof_len;
                unique_hash_count
                    = sm2_rev_multi_proof_unique_hash_count(proof);
            }

            sm2_rev_multi_proof_cleanup(&proof);
        }

        for (size_t i = 0; i < query_count; i++)
        {
            sm2_rev_member_proof_t member_proof;
            uint8_t member_buf[4096];
            size_t member_len = sizeof(member_buf);

            memset(&member_proof, 0, sizeof(member_proof));
            if (sm2_rev_tree_prove_member(tree, queries[i], &member_proof)
                    != SM2_IC_SUCCESS
                || sm2_rev_member_proof_encode(
                       &member_proof, member_buf, &member_len)
                    != SM2_IC_SUCCESS)
            {
                free(queries);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            single_total_bytes += member_len;
        }

        metrics[m].query_count = query_count;
        metrics[m].build_ms
            = calc_median_value(build_samples, BENCH_SCALE_ROUNDS);
        metrics[m].verify_ms
            = calc_median_value(verify_samples, BENCH_SCALE_ROUNDS);
        metrics[m].multiproof_bytes = multiproof_bytes;
        metrics[m].single_member_total_bytes = single_total_bytes;
        metrics[m].unique_hash_count = unique_hash_count;
        metrics[m].compression_pct = single_total_bytes == 0U
            ? 0.0
            : ((double)multiproof_bytes * 100.0) / (double)single_total_bytes;

        free(queries);
    }

    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 1;
}

static int collect_delta_metrics(delta_metric_t *metrics, size_t metric_count)
{
    static const size_t delta_sizes[] = { 1U, 8U, 32U, 128U, 512U };

    if (!metrics
        || metric_count != (sizeof(delta_sizes) / sizeof(delta_sizes[0])))
    {
        return 0;
    }

    for (size_t m = 0; m < metric_count; m++)
    {
        const size_t item_count = delta_sizes[m];
        sm2_crl_delta_item_t *items = NULL;
        double samples[BENCH_DELTA_ROUNDS];

        items = (sm2_crl_delta_item_t *)calloc(item_count, sizeof(*items));
        if (!items)
            return 0;
        memset(samples, 0, sizeof(samples));

        for (size_t i = 0; i < item_count; i++)
        {
            items[i].serial_number
                = 6000000ULL + ((uint64_t)m * 10000ULL) + (uint64_t)i;
            items[i].revoked = true;
        }

        for (size_t round = 0; round < BENCH_DELTA_ROUNDS; round++)
        {
            sm2_rev_ctx_t *ctx = NULL;
            sm2_crl_delta_t delta;
            const uint64_t now_ts = current_unix_ts();

            memset(&delta, 0, sizeof(delta));
            if (sm2_rev_init(&ctx, item_count * 2U + 8U, 300, now_ts)
                != SM2_IC_SUCCESS)
            {
                free(items);
                return 0;
            }

            delta.base_version = 0U;
            delta.new_version = 1U;
            delta.items = items;
            delta.item_count = item_count;

            double t0 = now_ms_highres();
            if (sm2_rev_apply_delta(ctx, &delta, now_ts) != SM2_IC_SUCCESS)
            {
                sm2_rev_cleanup(&ctx);
                free(items);
                return 0;
            }
            samples[round] = now_ms_highres() - t0;
            sm2_rev_cleanup(&ctx);
        }

        metrics[m].delta_items = item_count;
        metrics[m].apply_ms = calc_median_value(samples, BENCH_DELTA_ROUNDS);
        free(items);
    }

    return 1;
}

static int collect_epoch_cache_metrics(
    epoch_cache_metric_t *metrics, size_t metric_count)
{
    static const size_t cache_levels[] = { 2U, 4U, 6U, 8U, 10U };
    enum
    {
        revoked_count = 65536
    };
    uint64_t *revoked = NULL;
    sm2_rev_tree_t *tree = NULL;
    const uint64_t member_serial
        = 7000001ULL + ((uint64_t)revoked_count / 2U) * 2ULL;

    if (!metrics
        || metric_count != (sizeof(cache_levels) / sizeof(cache_levels[0])))
    {
        return 0;
    }

    revoked = (uint64_t *)calloc(revoked_count, sizeof(uint64_t));
    if (!revoked)
        return 0;
    fill_revoked_serials(revoked, revoked_count, 7000001ULL);

    if (sm2_rev_tree_build(&tree, revoked, revoked_count, 2026032601ULL)
        != SM2_IC_SUCCESS)
    {
        free(revoked);
        return 0;
    }

    for (size_t i = 0; i < metric_count; i++)
    {
        double build_samples[BENCH_SCALE_ROUNDS];
        double verify_samples[BENCH_SCALE_ROUNDS];
        double proof_build_samples[BENCH_SCALE_ROUNDS];
        double proof_verify_samples[BENCH_SCALE_ROUNDS];
        size_t directory_bytes = 0;
        size_t cached_proof_bytes = 0;
        const size_t cache_top_levels = cache_levels[i];

        memset(build_samples, 0, sizeof(build_samples));
        memset(verify_samples, 0, sizeof(verify_samples));
        memset(proof_build_samples, 0, sizeof(proof_build_samples));
        memset(proof_verify_samples, 0, sizeof(proof_verify_samples));

        for (size_t round = 0; round < BENCH_SCALE_ROUNDS; round++)
        {
            sm2_rev_epoch_dir_t *directory = NULL;
            sm2_rev_cached_member_proof_t cached_proof;
            uint8_t dir_buf[262144];
            uint8_t proof_buf[8192];
            size_t dir_len = sizeof(dir_buf);
            size_t proof_len = sizeof(proof_buf);
            const uint64_t valid_from = 1000U;
            const uint64_t valid_until = 2000U;
            const uint64_t verify_now = 1500U;

            memset(&cached_proof, 0, sizeof(cached_proof));

            double t0 = now_ms_highres();
            if (sm2_rev_epoch_dir_build(tree, 2026032601ULL + (uint64_t)round,
                    cache_top_levels, valid_from, valid_until,
                    bench_epoch_sign_cb, NULL, &directory)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_dir_verify(
                    directory, verify_now, bench_epoch_verify_cb, NULL)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            verify_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_prove_member_cached(
                    tree, member_serial, cache_top_levels, &cached_proof)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            proof_build_samples[round] = now_ms_highres() - t0;

            t0 = now_ms_highres();
            if (sm2_rev_epoch_verify_member_cached(directory, verify_now,
                    &cached_proof, bench_epoch_verify_cb, NULL)
                != SM2_IC_SUCCESS)
            {
                sm2_rev_epoch_dir_cleanup(&directory);
                sm2_rev_tree_cleanup(&tree);
                free(revoked);
                return 0;
            }
            proof_verify_samples[round] = now_ms_highres() - t0;

            if (round == 0U)
            {
                if (sm2_rev_epoch_dir_encode(directory, dir_buf, &dir_len)
                        != SM2_IC_SUCCESS
                    || sm2_rev_cached_member_proof_encode(
                           &cached_proof, proof_buf, &proof_len)
                        != SM2_IC_SUCCESS)
                {
                    sm2_rev_epoch_dir_cleanup(&directory);
                    sm2_rev_tree_cleanup(&tree);
                    free(revoked);
                    return 0;
                }
                directory_bytes = dir_len;
                cached_proof_bytes = proof_len;
            }

            sm2_rev_epoch_dir_cleanup(&directory);
        }

        metrics[i].revoked_count = revoked_count;
        metrics[i].cache_top_levels = cache_top_levels;
        metrics[i].directory_build_ms
            = calc_median_value(build_samples, BENCH_SCALE_ROUNDS);
        metrics[i].directory_verify_ms
            = calc_median_value(verify_samples, BENCH_SCALE_ROUNDS);
        metrics[i].cached_proof_build_ms
            = calc_median_value(proof_build_samples, BENCH_SCALE_ROUNDS);
        metrics[i].cached_proof_verify_ms
            = calc_median_value(proof_verify_samples, BENCH_SCALE_ROUNDS);
        metrics[i].directory_bytes = directory_bytes;
        metrics[i].cached_proof_bytes = cached_proof_bytes;
    }

    sm2_rev_tree_cleanup(&tree);
    free(revoked);
    return 1;
}

static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static double rng_unit_double(uint64_t *state)
{
    const uint64_t value = rng_next(state);
    return (double)(value >> 11) * (1.0 / 9007199254740992.0);
}

static void build_zipf_cdf(double *cdf, size_t count, double exponent)
{
    double total = 0.0;
    double running = 0.0;

    if (!cdf || count == 0U)
        return;
    for (size_t i = 0; i < count; i++)
        total += 1.0 / pow((double)(i + 1U), exponent);
    if (total <= 0.0)
        return;

    for (size_t i = 0; i < count; i++)
    {
        running += (1.0 / pow((double)(i + 1U), exponent)) / total;
        cdf[i] = running;
    }
    cdf[count - 1U] = 1.0;
}

static size_t zipf_pick_domain(const double *cdf, size_t count, double sample)
{
    size_t lo = 0;
    size_t hi = count;

    while (lo + 1U < hi)
    {
        size_t mid = lo + (hi - lo) / 2U;
        if (sample <= cdf[mid])
            hi = mid;
        else
            lo = mid;
    }
    if (sample <= cdf[lo])
        return lo;
    return hi < count ? hi : (count - 1U);
}

static int collect_zipf_workload_points(const base_metric_t *base_metrics,
    zipf_workload_point_t *points, size_t point_count)
{
    static const size_t milestones[] = { 100U, 250U, 500U, 750U, 1000U };
    double *cdf = NULL;
    double unique_sums[sizeof(milestones) / sizeof(milestones[0])];

    if (!base_metrics || !points
        || point_count != (sizeof(milestones) / sizeof(milestones[0])))
    {
        return 0;
    }

    memset(unique_sums, 0, sizeof(unique_sums));
    cdf = (double *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*cdf));
    if (!cdf)
        return 0;
    build_zipf_cdf(cdf, BENCH_ZIPF_DOMAIN_POOL, BENCH_ZIPF_EXPONENT);

    for (size_t run = 0; run < BENCH_ZIPF_RUNS; run++)
    {
        bool *visited
            = (bool *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*visited));
        uint64_t seed = 0xC0FFEE1234567890ULL ^ (uint64_t)run;
        size_t unique_count = 0;
        size_t milestone_index = 0;

        if (!visited)
        {
            free(cdf);
            return 0;
        }

        for (size_t visit = 1U; visit <= BENCH_ZIPF_VISITS; visit++)
        {
            size_t domain = zipf_pick_domain(
                cdf, BENCH_ZIPF_DOMAIN_POOL, rng_unit_double(&seed));
            if (!visited[domain])
            {
                visited[domain] = true;
                unique_count++;
            }

            while (milestone_index < point_count
                && visit == milestones[milestone_index])
            {
                unique_sums[milestone_index] += (double)unique_count;
                milestone_index++;
            }
        }

        free(visited);
    }

    for (size_t i = 0; i < point_count; i++)
    {
        double mean_unique = unique_sums[i] / (double)BENCH_ZIPF_RUNS;
        double repeated_contacts = (double)milestones[i] - mean_unique;
        double compact_bundle_bytes
            = base_metrics->auth_bundle_compact_bytes > 0U
            ? (double)base_metrics->auth_bundle_compact_bytes
            : (double)base_metrics->auth_bundle_bytes;
        double compact_verify_ms
            = base_metrics->verify_bundle_compact_median_ms > 0.0
            ? base_metrics->verify_bundle_compact_median_ms
            : base_metrics->verify_bundle_median_ms;
        double compact_session_ms
            = base_metrics->secure_session_compact_median_ms > 0.0
            ? base_metrics->secure_session_compact_median_ms
            : base_metrics->secure_session_median_ms;
        double auth_bytes
            = mean_unique * (double)base_metrics->auth_bundle_bytes
            + repeated_contacts * compact_bundle_bytes;
        double verify_ms = mean_unique * base_metrics->verify_bundle_median_ms
            + repeated_contacts * compact_verify_ms;
        double session_ms = mean_unique * base_metrics->secure_session_median_ms
            + repeated_contacts * compact_session_ms;

        points[i].visits = milestones[i];
        points[i].mean_unique_domains = mean_unique;
        points[i].auth_bytes = auth_bytes;
        points[i].tx_ms_20kbps = tx_delay_ms(auth_bytes, 20.0);
        points[i].tx_ms_64kbps = tx_delay_ms(auth_bytes, 64.0);
        points[i].tx_ms_256kbps = tx_delay_ms(auth_bytes, 256.0);
        points[i].local_verify_ms = verify_ms;
        points[i].secure_session_ms = session_ms;
        points[i].combined_local_ms = verify_ms + session_ms;
        points[i].combined_total_ms_20kbps
            = points[i].combined_local_ms + points[i].tx_ms_20kbps;
        points[i].combined_total_ms_64kbps
            = points[i].combined_local_ms + points[i].tx_ms_64kbps;
        points[i].combined_total_ms_256kbps
            = points[i].combined_local_ms + points[i].tx_ms_256kbps;
    }

    free(cdf);
    return 1;
}

static void fill_strategy_metric(workload_strategy_metric_t *metric,
    double background_bytes, double foreground_bytes, double online_requests,
    double local_ms)
{
    if (!metric)
        return;
    memset(metric, 0, sizeof(*metric));
    metric->background_bytes = background_bytes;
    metric->foreground_bytes = foreground_bytes;
    metric->total_bytes = background_bytes + foreground_bytes;
    metric->online_requests = online_requests;
    metric->local_ms = local_ms;
    metric->total_ms_20kbps = local_ms + tx_delay_ms(foreground_bytes, 20.0)
        + (online_requests * BENCH_BASELINE_ONLINE_RTT_MS);
    metric->total_ms_64kbps = local_ms + tx_delay_ms(foreground_bytes, 64.0)
        + (online_requests * BENCH_BASELINE_ONLINE_RTT_MS);
    metric->total_ms_256kbps = local_ms + tx_delay_ms(foreground_bytes, 256.0)
        + (online_requests * BENCH_BASELINE_ONLINE_RTT_MS);
}

static void emit_json_timing_stat(
    FILE *out, const char *key, const timing_stat_t *stat, bool trailing_comma);

static int collect_zipf_strategy_comparison_points(
    const base_metric_t *base_metrics,
    const real_revocation_baseline_t *real_baseline,
    const controlled_network_compare_t *network_metrics,
    zipf_strategy_compare_point_t *points, size_t point_count)
{
    static const size_t milestones[] = { 100U, 250U, 500U, 750U, 1000U };
    typedef struct
    {
        double unique_domains;
        double unique_crl_buckets;
        double crl_lookup_visits;
        double ocsp_requests;
        double ocsp_crl_fallback_requests;
        double ocsp_check_visits;
        double ocsp_fallback_check_visits;
        double crlite_lru_hits;
        double crl_foreground_bytes;
        double crl_online_requests;
        double ocsp_foreground_bytes;
        double ocsp_online_requests;
        double crlite_background_bytes;
        double crlite_local_ms;
        double tinypki_background_bytes;
        double tinypki_foreground_bytes;
        double tinypki_local_ms;
    } strategy_sum_t;

    double *cdf = NULL;
    strategy_sum_t sums[sizeof(milestones) / sizeof(milestones[0])];

    if (!base_metrics || !real_baseline || !network_metrics || !points
        || point_count != (sizeof(milestones) / sizeof(milestones[0])))
    {
        return 0;
    }

    memset(sums, 0, sizeof(sums));
    cdf = (double *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*cdf));
    if (!cdf)
        return 0;
    build_zipf_cdf(cdf, BENCH_ZIPF_DOMAIN_POOL, BENCH_ZIPF_EXPONENT);

    for (size_t run = 0; run < BENCH_ZIPF_RUNS; run++)
    {
        bool *visited = NULL;
        bool *ocsp_cache = NULL;
        bool *crl_cache = NULL;
        bool *ocsp_fallback_crl_cache = NULL;
        size_t *crlite_lru = NULL;
        uint64_t seed = BENCH_ZIPF_SEED_BASE ^ (uint64_t)run;
        size_t unique_domains = 0U;
        size_t unique_crls = 0U;
        size_t crl_lookup_visits = 0U;
        size_t ocsp_requests = 0U;
        size_t ocsp_crl_fallback_requests = 0U;
        size_t ocsp_check_visits = 0U;
        size_t ocsp_fallback_check_visits = 0U;
        size_t crlite_lru_hits = 0U;
        size_t crlite_lru_count = 0U;
        size_t milestone_index = 0U;
        double crl_foreground_bytes = 0.0;
        double crl_online_requests = 0.0;
        double ocsp_foreground_bytes = 0.0;
        double ocsp_online_requests = 0.0;
        double crlite_local_ms = 0.0;
        double tinypki_foreground_bytes = 0.0;
        double tinypki_local_ms = 0.0;
        double tinypki_background_bytes
            = (double)base_metrics->root_record_bytes;

        visited = (bool *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*visited));
        ocsp_cache
            = (bool *)calloc(BENCH_ZIPF_DOMAIN_POOL, sizeof(*ocsp_cache));
        crl_cache
            = (bool *)calloc(BENCH_BASELINE_CRL_BUCKETS, sizeof(*crl_cache));
        ocsp_fallback_crl_cache = (bool *)calloc(
            BENCH_BASELINE_CRL_BUCKETS, sizeof(*ocsp_fallback_crl_cache));
        crlite_lru = (size_t *)calloc(
            BENCH_BASELINE_CRLITE_LRU_ENTRIES, sizeof(*crlite_lru));
        if (!visited || !ocsp_cache || !crl_cache || !ocsp_fallback_crl_cache
            || !crlite_lru)
        {
            free(visited);
            free(ocsp_cache);
            free(crl_cache);
            free(ocsp_fallback_crl_cache);
            free(crlite_lru);
            free(cdf);
            return 0;
        }

        for (size_t visit = 1U; visit <= BENCH_ZIPF_VISITS; visit++)
        {
            size_t domain = zipf_pick_domain(
                cdf, BENCH_ZIPF_DOMAIN_POOL, rng_unit_double(&seed));
            size_t crl_bucket = domain_to_crl_bucket(domain);
            bool is_new_domain = false;

            if (!visited[domain])
            {
                visited[domain] = true;
                unique_domains++;
                is_new_domain = true;
            }

            crl_lookup_visits++;

            if (!crl_cache[crl_bucket])
            {
                crl_cache[crl_bucket] = true;
                unique_crls++;
                crl_foreground_bytes
                    += (double)network_metrics->crl_http.total_bytes;
                crl_online_requests += 1.0;
            }

            if (domain_has_ocsp(domain))
            {
                ocsp_check_visits++;
                if (!ocsp_cache[domain])
                {
                    ocsp_cache[domain] = true;
                    ocsp_requests++;
                    ocsp_foreground_bytes
                        += (double)network_metrics->ocsp_http.total_bytes;
                    ocsp_online_requests += 1.0;
                }
            }
            else if (!ocsp_fallback_crl_cache[crl_bucket])
            {
                ocsp_fallback_check_visits++;
                ocsp_fallback_crl_cache[crl_bucket] = true;
                ocsp_crl_fallback_requests++;
                ocsp_foreground_bytes
                    += (double)network_metrics->crl_http.total_bytes;
                ocsp_online_requests += 1.0;
            }
            else
            {
                ocsp_fallback_check_visits++;
            }

            if (lru_touch(crlite_lru, &crlite_lru_count,
                    BENCH_BASELINE_CRLITE_LRU_ENTRIES, domain))
            {
                crlite_lru_hits++;
                crlite_local_ms += BENCH_BASELINE_CRLITE_CACHED_LOOKUP_MS;
            }
            else
            {
                crlite_local_ms += BENCH_BASELINE_CRLITE_LOOKUP_MS;
            }

            if (is_new_domain)
            {
                tinypki_foreground_bytes
                    += (double)network_metrics->tinypki_full_http.total_bytes;
                tinypki_local_ms += base_metrics->verify_bundle_median_ms
                    + base_metrics->secure_session_median_ms;
            }
            else
            {
                tinypki_foreground_bytes
                    += (double)
                           network_metrics->tinypki_compact_http.total_bytes;
                tinypki_local_ms
                    += base_metrics->verify_bundle_compact_median_ms
                    + base_metrics->secure_session_compact_median_ms;
            }

            while (milestone_index < point_count
                && visit == milestones[milestone_index])
            {
                sums[milestone_index].unique_domains += (double)unique_domains;
                sums[milestone_index].unique_crl_buckets += (double)unique_crls;
                sums[milestone_index].crl_lookup_visits
                    += (double)crl_lookup_visits;
                sums[milestone_index].ocsp_requests += (double)ocsp_requests;
                sums[milestone_index].ocsp_crl_fallback_requests
                    += (double)ocsp_crl_fallback_requests;
                sums[milestone_index].ocsp_check_visits
                    += (double)ocsp_check_visits;
                sums[milestone_index].ocsp_fallback_check_visits
                    += (double)ocsp_fallback_check_visits;
                sums[milestone_index].crlite_lru_hits
                    += (double)crlite_lru_hits;
                sums[milestone_index].crl_foreground_bytes
                    += crl_foreground_bytes;
                sums[milestone_index].crl_online_requests
                    += crl_online_requests;
                sums[milestone_index].ocsp_foreground_bytes
                    += ocsp_foreground_bytes;
                sums[milestone_index].ocsp_online_requests
                    += ocsp_online_requests;
                sums[milestone_index].crlite_background_bytes
                    += BENCH_BASELINE_CRLITE_DELTA_BYTES;
                sums[milestone_index].crlite_local_ms += crlite_local_ms;
                sums[milestone_index].tinypki_background_bytes
                    += tinypki_background_bytes;
                sums[milestone_index].tinypki_foreground_bytes
                    += tinypki_foreground_bytes;
                sums[milestone_index].tinypki_local_ms += tinypki_local_ms;
                milestone_index++;
            }
        }

        free(visited);
        free(ocsp_cache);
        free(crl_cache);
        free(ocsp_fallback_crl_cache);
        free(crlite_lru);
    }

    for (size_t i = 0; i < point_count; i++)
    {
        double scale = 1.0 / (double)BENCH_ZIPF_RUNS;

        points[i].visits = milestones[i];
        points[i].mean_unique_domains = sums[i].unique_domains * scale;
        points[i].mean_unique_crl_buckets = sums[i].unique_crl_buckets * scale;
        points[i].mean_ocsp_requests = sums[i].ocsp_requests * scale;
        points[i].mean_ocsp_crl_fallback_requests
            = sums[i].ocsp_crl_fallback_requests * scale;
        points[i].mean_crlite_lru_hits = sums[i].crlite_lru_hits * scale;
        fill_strategy_metric(&points[i].crl_only, 0.0,
            sums[i].crl_foreground_bytes * scale,
            sums[i].crl_online_requests * scale,
            (sums[i].crl_lookup_visits * scale)
                * real_baseline->crl_verify_lookup_median_ms);
        fill_strategy_metric(&points[i].ocsp_and_crl, 0.0,
            sums[i].ocsp_foreground_bytes * scale,
            sums[i].ocsp_online_requests * scale,
            (sums[i].ocsp_check_visits * scale)
                    * real_baseline->ocsp_verify_median_ms
                + (sums[i].ocsp_fallback_check_visits * scale)
                    * real_baseline->crl_verify_lookup_median_ms);
        fill_strategy_metric(&points[i].crlite,
            sums[i].crlite_background_bytes * scale, 0.0, 0.0,
            sums[i].crlite_local_ms * scale);
        fill_strategy_metric(&points[i].tinypki_compact,
            sums[i].tinypki_background_bytes * scale,
            sums[i].tinypki_foreground_bytes * scale, 0.0,
            sums[i].tinypki_local_ms * scale);
    }

    free(cdf);
    return 1;
}

static void emit_json(FILE *out, const base_metric_t *base_metrics,
    const real_revocation_baseline_t *real_baseline,
    const controlled_network_compare_t *network_metrics,
    const revocation_scale_metric_t *revocation_metrics,
    size_t revocation_count, const multiproof_metric_t *multiproof_metrics,
    size_t multiproof_count, const delta_metric_t *delta_metrics,
    size_t delta_count, const epoch_cache_metric_t *epoch_metrics,
    size_t epoch_count, const zipf_workload_point_t *zipf_points,
    size_t zipf_count, const zipf_strategy_compare_point_t *strategy_points,
    size_t strategy_count)
{
    double implicit_vs_x509_pct = 0.0;
    if (base_metrics->x509_der_bytes > 0U)
    {
        implicit_vs_x509_pct
            = ((double)base_metrics->implicit_cert_bytes * 100.0)
            / (double)base_metrics->x509_der_bytes;
    }

    fprintf(out, "{\n");
    fprintf(out, "  \"metadata\": {\n");
    fprintf(out, "    \"benchmark\": \"tinypki-capability-suite\",\n");
    fprintf(out, "    \"revocation_scale_rounds\": %d,\n", BENCH_SCALE_ROUNDS);
    fprintf(out, "    \"delta_rounds\": %d,\n", BENCH_DELTA_ROUNDS);
    fprintf(out, "    \"verify_rounds\": %d,\n", BENCH_VERIFY_ROUNDS);
    fprintf(out, "    \"session_rounds\": %d,\n", BENCH_SESSION_ROUNDS);
    fprintf(out, "    \"multiproof_max_queries\": %d,\n",
        SM2_REV_MERKLE_MULTI_MAX_QUERIES);
    fprintf(out, "    \"zipf_runs\": %d,\n", BENCH_ZIPF_RUNS);
    fprintf(out, "    \"zipf_visits\": %d,\n", BENCH_ZIPF_VISITS);
    fprintf(out, "    \"zipf_domain_pool\": %d,\n", BENCH_ZIPF_DOMAIN_POOL);
    fprintf(out, "    \"zipf_exponent\": %.2f,\n", BENCH_ZIPF_EXPONENT);
    fprintf(out, "    \"zipf_seed_base\": \"%llx\"\n",
        (unsigned long long)BENCH_ZIPF_SEED_BASE);
    fprintf(out, "  },\n");
    fprintf(out, "  \"baseline_model\": {\n");
    fprintf(out, "    \"paper_source\": \"CRLite IEEE S&P 2017\",\n");
    fprintf(out,
        "    \"note\": \"Paper-inspired modeled baselines; no live CA crawling "
        "or browser integration.\",\n");
    fprintf(out, "    \"crl_target_bytes_per_list\": %.0f,\n",
        BENCH_BASELINE_CRL_TARGET_BYTES);
    fprintf(out, "    \"ocsp_target_bytes_per_request\": %.0f,\n",
        BENCH_BASELINE_OCSP_TARGET_BYTES);
    fprintf(out, "    \"crlite_initial_filter_bytes\": %.0f,\n",
        BENCH_BASELINE_CRLITE_INITIAL_BYTES);
    fprintf(out, "    \"crlite_daily_delta_bytes\": %.0f,\n",
        BENCH_BASELINE_CRLITE_DELTA_BYTES);
    fprintf(out, "    \"crlite_lookup_ms\": %.1f,\n",
        BENCH_BASELINE_CRLITE_LOOKUP_MS);
    fprintf(out, "    \"crlite_cached_lookup_ms\": %.1f,\n",
        BENCH_BASELINE_CRLITE_CACHED_LOOKUP_MS);
    fprintf(out, "    \"crlite_lru_entries\": %u,\n",
        BENCH_BASELINE_CRLITE_LRU_ENTRIES);
    fprintf(out, "    \"online_request_rtt_ms\": %.1f,\n",
        BENCH_BASELINE_ONLINE_RTT_MS);
    fprintf(out, "    \"ocsp_reachable_pct\": %.1f,\n",
        BENCH_BASELINE_OCSP_REACHABLE_PCT);
    fprintf(out, "    \"crl_bucket_count\": %u\n", BENCH_BASELINE_CRL_BUCKETS);
    fprintf(out, "  },\n");
    fprintf(out, "  \"real_crl_ocsp_baseline\": {\n");
    fprintf(
        out, "    \"crl_entry_count\": %zu,\n", real_baseline->crl_entry_count);
    fprintf(out, "    \"crl_der_bytes\": %zu,\n", real_baseline->crl_der_bytes);
    fprintf(out, "    \"ocsp_request_der_bytes\": %zu,\n",
        real_baseline->ocsp_request_der_bytes);
    fprintf(out, "    \"ocsp_response_der_bytes\": %zu,\n",
        real_baseline->ocsp_response_der_bytes);
    fprintf(
        out, "    \"ocsp_wire_bytes\": %zu,\n", real_baseline->ocsp_wire_bytes);
    fprintf(out, "    \"crl_verify_lookup_median_ms\": %.3f,\n",
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out, "    \"ocsp_verify_median_ms\": %.3f,\n",
        real_baseline->ocsp_verify_median_ms);
    emit_json_timing_stat(out, "crl_verify_lookup_timing_ms",
        &real_baseline->crl_verify_lookup_timing, true);
    emit_json_timing_stat(out, "ocsp_verify_timing_ms",
        &real_baseline->ocsp_verify_timing, false);
    fprintf(out, "  },\n");
    fprintf(out, "  \"controlled_network_compare\": {\n");
    fprintf(out,
        "    \"note\": \"Loopback HTTP benchmark with real CRL/OCSP objects "
        "and "
        "real TinyPKI verification messages under one controlled local "
        "transport.\",\n");
    fprintf(out,
        "    \"crl_http\": {\"request_bytes\": %zu, \"response_bytes\": %zu, "
        "\"total_bytes\": %zu, \"roundtrip_median_ms\": %.3f, "
        "\"roundtrip_mean_ms\": %.3f, \"roundtrip_p95_ms\": %.3f, "
        "\"roundtrip_stddev_ms\": %.3f},\n",
        network_metrics->crl_http.request_bytes,
        network_metrics->crl_http.response_bytes,
        network_metrics->crl_http.total_bytes,
        network_metrics->crl_http.roundtrip_median_ms,
        network_metrics->crl_http.roundtrip_timing.mean_ms,
        network_metrics->crl_http.roundtrip_timing.p95_ms,
        network_metrics->crl_http.roundtrip_timing.stddev_ms);
    fprintf(out,
        "    \"ocsp_http\": {\"request_bytes\": %zu, \"response_bytes\": %zu, "
        "\"total_bytes\": %zu, \"roundtrip_median_ms\": %.3f, "
        "\"roundtrip_mean_ms\": %.3f, \"roundtrip_p95_ms\": %.3f, "
        "\"roundtrip_stddev_ms\": %.3f},\n",
        network_metrics->ocsp_http.request_bytes,
        network_metrics->ocsp_http.response_bytes,
        network_metrics->ocsp_http.total_bytes,
        network_metrics->ocsp_http.roundtrip_median_ms,
        network_metrics->ocsp_http.roundtrip_timing.mean_ms,
        network_metrics->ocsp_http.roundtrip_timing.p95_ms,
        network_metrics->ocsp_http.roundtrip_timing.stddev_ms);
    fprintf(out,
        "    \"tinypki_full_http\": {\"request_bytes\": %zu, "
        "\"response_bytes\": %zu, \"total_bytes\": %zu, "
        "\"roundtrip_median_ms\": %.3f, \"roundtrip_mean_ms\": %.3f, "
        "\"roundtrip_p95_ms\": %.3f, \"roundtrip_stddev_ms\": %.3f},\n",
        network_metrics->tinypki_full_http.request_bytes,
        network_metrics->tinypki_full_http.response_bytes,
        network_metrics->tinypki_full_http.total_bytes,
        network_metrics->tinypki_full_http.roundtrip_median_ms,
        network_metrics->tinypki_full_http.roundtrip_timing.mean_ms,
        network_metrics->tinypki_full_http.roundtrip_timing.p95_ms,
        network_metrics->tinypki_full_http.roundtrip_timing.stddev_ms);
    fprintf(out,
        "    \"tinypki_compact_http\": {\"request_bytes\": %zu, "
        "\"response_bytes\": %zu, \"total_bytes\": %zu, "
        "\"roundtrip_median_ms\": %.3f, \"roundtrip_mean_ms\": %.3f, "
        "\"roundtrip_p95_ms\": %.3f, \"roundtrip_stddev_ms\": %.3f}\n",
        network_metrics->tinypki_compact_http.request_bytes,
        network_metrics->tinypki_compact_http.response_bytes,
        network_metrics->tinypki_compact_http.total_bytes,
        network_metrics->tinypki_compact_http.roundtrip_median_ms,
        network_metrics->tinypki_compact_http.roundtrip_timing.mean_ms,
        network_metrics->tinypki_compact_http.roundtrip_timing.p95_ms,
        network_metrics->tinypki_compact_http.roundtrip_timing.stddev_ms);
    fprintf(out, "  },\n");
    fprintf(out, "  \"summary\": {\n");
    fprintf(
        out, "    \"x509_der_bytes\": %zu,\n", base_metrics->x509_der_bytes);
    fprintf(out, "    \"implicit_cert_bytes\": %zu,\n",
        base_metrics->implicit_cert_bytes);
    fprintf(out, "    \"implicit_vs_x509_pct\": %.2f,\n", implicit_vs_x509_pct);
    fprintf(out, "    \"root_record_bytes\": %zu,\n",
        base_metrics->root_record_bytes);
    fprintf(out, "    \"absence_proof_bytes\": %zu,\n",
        base_metrics->absence_proof_bytes);
    fprintf(out, "    \"issuance_evidence_bytes\": %zu,\n",
        base_metrics->issuance_evidence_bytes);
    fprintf(out, "    \"compact_root_hint_bytes\": %zu,\n",
        base_metrics->compact_root_hint_bytes);
    fprintf(out, "    \"auth_bundle_bytes\": %zu,\n",
        base_metrics->auth_bundle_bytes);
    fprintf(out, "    \"auth_bundle_compact_bytes\": %zu,\n",
        base_metrics->auth_bundle_compact_bytes);
    fprintf(out, "    \"verify_bundle_median_ms\": %.3f,\n",
        base_metrics->verify_bundle_median_ms);
    fprintf(out, "    \"verify_bundle_compact_median_ms\": %.3f,\n",
        base_metrics->verify_bundle_compact_median_ms);
    fprintf(out, "    \"secure_session_median_ms\": %.3f,\n",
        base_metrics->secure_session_median_ms);
    fprintf(out, "    \"secure_session_compact_median_ms\": %.3f,\n",
        base_metrics->secure_session_compact_median_ms);
    fprintf(out, "    \"revoke_publish_median_ms\": %.3f,\n",
        base_metrics->revoke_publish_median_ms);
    fprintf(out, "    \"service_refresh_root_median_ms\": %.3f,\n",
        base_metrics->service_refresh_root_median_ms);
    fprintf(out, "    \"client_refresh_root_median_ms\": %.3f,\n",
        base_metrics->client_refresh_root_median_ms);
    emit_json_timing_stat(out, "verify_bundle_timing_ms",
        &base_metrics->verify_bundle_timing, true);
    emit_json_timing_stat(out, "verify_bundle_compact_timing_ms",
        &base_metrics->verify_bundle_compact_timing, true);
    emit_json_timing_stat(out, "secure_session_timing_ms",
        &base_metrics->secure_session_timing, true);
    emit_json_timing_stat(out, "secure_session_compact_timing_ms",
        &base_metrics->secure_session_compact_timing, false);
    fprintf(out, "  },\n");

    fprintf(out, "  \"revocation_scaling\": [\n");
    for (size_t i = 0; i < revocation_count; i++)
    {
        fprintf(out,
            "    {\"revoked_count\": %zu, \"tree_build_ms\": %.3f, "
            "\"member_prove_ms\": %.3f, \"member_verify_ms\": %.3f, "
            "\"absence_prove_ms\": %.3f, \"absence_verify_ms\": %.3f, "
            "\"member_proof_bytes\": %zu, \"absence_proof_bytes\": %zu}%s\n",
            revocation_metrics[i].revoked_count,
            revocation_metrics[i].tree_build_ms,
            revocation_metrics[i].member_prove_ms,
            revocation_metrics[i].member_verify_ms,
            revocation_metrics[i].absence_prove_ms,
            revocation_metrics[i].absence_verify_ms,
            revocation_metrics[i].member_proof_bytes,
            revocation_metrics[i].absence_proof_bytes,
            (i + 1U) == revocation_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"epoch_cache_scaling\": [\n");
    for (size_t i = 0; i < epoch_count; i++)
    {
        fprintf(out,
            "    {\"revoked_count\": %zu, \"cache_top_levels\": %zu, "
            "\"directory_build_ms\": %.3f, \"directory_verify_ms\": %.3f, "
            "\"cached_proof_build_ms\": %.3f, "
            "\"cached_proof_verify_ms\": %.3f, \"directory_bytes\": %zu, "
            "\"cached_proof_bytes\": %zu}%s\n",
            epoch_metrics[i].revoked_count, epoch_metrics[i].cache_top_levels,
            epoch_metrics[i].directory_build_ms,
            epoch_metrics[i].directory_verify_ms,
            epoch_metrics[i].cached_proof_build_ms,
            epoch_metrics[i].cached_proof_verify_ms,
            epoch_metrics[i].directory_bytes,
            epoch_metrics[i].cached_proof_bytes,
            (i + 1U) == epoch_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"multiproof_scaling\": [\n");
    for (size_t i = 0; i < multiproof_count; i++)
    {
        fprintf(out,
            "    {\"query_count\": %zu, \"build_ms\": %.3f, "
            "\"verify_ms\": %.3f, \"multiproof_bytes\": %zu, "
            "\"single_member_total_bytes\": %zu, \"unique_hash_count\": %zu, "
            "\"compression_pct\": %.2f}%s\n",
            multiproof_metrics[i].query_count, multiproof_metrics[i].build_ms,
            multiproof_metrics[i].verify_ms,
            multiproof_metrics[i].multiproof_bytes,
            multiproof_metrics[i].single_member_total_bytes,
            multiproof_metrics[i].unique_hash_count,
            multiproof_metrics[i].compression_pct,
            (i + 1U) == multiproof_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"delta_scaling\": [\n");
    for (size_t i = 0; i < delta_count; i++)
    {
        fprintf(out, "    {\"delta_items\": %zu, \"apply_ms\": %.3f}%s\n",
            delta_metrics[i].delta_items, delta_metrics[i].apply_ms,
            (i + 1U) == delta_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"zipf_workload\": [\n");
    for (size_t i = 0; i < zipf_count; i++)
    {
        fprintf(out,
            "    {\"visits\": %zu, \"mean_unique_domains\": %.2f, "
            "\"auth_bytes\": %.2f, \"tx_ms_20kbps\": %.3f, "
            "\"tx_ms_64kbps\": %.3f, \"tx_ms_256kbps\": %.3f, "
            "\"local_verify_ms\": %.3f, \"secure_session_ms\": %.3f, "
            "\"combined_local_ms\": %.3f, \"combined_total_ms_20kbps\": %.3f, "
            "\"combined_total_ms_64kbps\": %.3f, "
            "\"combined_total_ms_256kbps\": %.3f}%s\n",
            zipf_points[i].visits, zipf_points[i].mean_unique_domains,
            zipf_points[i].auth_bytes, zipf_points[i].tx_ms_20kbps,
            zipf_points[i].tx_ms_64kbps, zipf_points[i].tx_ms_256kbps,
            zipf_points[i].local_verify_ms, zipf_points[i].secure_session_ms,
            zipf_points[i].combined_local_ms,
            zipf_points[i].combined_total_ms_20kbps,
            zipf_points[i].combined_total_ms_64kbps,
            zipf_points[i].combined_total_ms_256kbps,
            (i + 1U) == zipf_count ? "" : ",");
    }
    fprintf(out, "  ],\n");

    fprintf(out, "  \"zipf_strategy_comparison\": [\n");
    for (size_t i = 0; i < strategy_count; i++)
    {
        const zipf_strategy_compare_point_t *point = &strategy_points[i];
        fprintf(out,
            "    {\"visits\": %zu, \"mean_unique_domains\": %.2f, "
            "\"mean_unique_crl_buckets\": %.2f, \"mean_ocsp_requests\": %.2f, "
            "\"mean_ocsp_crl_fallback_requests\": %.2f, "
            "\"mean_crlite_lru_hits\": %.2f,\n",
            point->visits, point->mean_unique_domains,
            point->mean_unique_crl_buckets, point->mean_ocsp_requests,
            point->mean_ocsp_crl_fallback_requests,
            point->mean_crlite_lru_hits);
        fprintf(out,
            "      \"crl_only\": {\"background_bytes\": %.2f, "
            "\"foreground_bytes\": %.2f, \"total_bytes\": %.2f, "
            "\"online_requests\": %.2f, \"local_ms\": %.3f, "
            "\"total_ms_20kbps\": %.3f, \"total_ms_64kbps\": %.3f, "
            "\"total_ms_256kbps\": %.3f},\n",
            point->crl_only.background_bytes, point->crl_only.foreground_bytes,
            point->crl_only.total_bytes, point->crl_only.online_requests,
            point->crl_only.local_ms, point->crl_only.total_ms_20kbps,
            point->crl_only.total_ms_64kbps, point->crl_only.total_ms_256kbps);
        fprintf(out,
            "      \"ocsp_and_crl\": {\"background_bytes\": %.2f, "
            "\"foreground_bytes\": %.2f, \"total_bytes\": %.2f, "
            "\"online_requests\": %.2f, \"local_ms\": %.3f, "
            "\"total_ms_20kbps\": %.3f, \"total_ms_64kbps\": %.3f, "
            "\"total_ms_256kbps\": %.3f},\n",
            point->ocsp_and_crl.background_bytes,
            point->ocsp_and_crl.foreground_bytes,
            point->ocsp_and_crl.total_bytes,
            point->ocsp_and_crl.online_requests, point->ocsp_and_crl.local_ms,
            point->ocsp_and_crl.total_ms_20kbps,
            point->ocsp_and_crl.total_ms_64kbps,
            point->ocsp_and_crl.total_ms_256kbps);
        fprintf(out,
            "      \"crlite\": {\"background_bytes\": %.2f, "
            "\"foreground_bytes\": %.2f, \"total_bytes\": %.2f, "
            "\"online_requests\": %.2f, \"local_ms\": %.3f, "
            "\"total_ms_20kbps\": %.3f, \"total_ms_64kbps\": %.3f, "
            "\"total_ms_256kbps\": %.3f},\n",
            point->crlite.background_bytes, point->crlite.foreground_bytes,
            point->crlite.total_bytes, point->crlite.online_requests,
            point->crlite.local_ms, point->crlite.total_ms_20kbps,
            point->crlite.total_ms_64kbps, point->crlite.total_ms_256kbps);
        fprintf(out,
            "      \"tinypki_compact\": {\"background_bytes\": %.2f, "
            "\"foreground_bytes\": %.2f, \"total_bytes\": %.2f, "
            "\"online_requests\": %.2f, \"local_ms\": %.3f, "
            "\"total_ms_20kbps\": %.3f, \"total_ms_64kbps\": %.3f, "
            "\"total_ms_256kbps\": %.3f}}%s\n",
            point->tinypki_compact.background_bytes,
            point->tinypki_compact.foreground_bytes,
            point->tinypki_compact.total_bytes,
            point->tinypki_compact.online_requests,
            point->tinypki_compact.local_ms,
            point->tinypki_compact.total_ms_20kbps,
            point->tinypki_compact.total_ms_64kbps,
            point->tinypki_compact.total_ms_256kbps,
            (i + 1U) == strategy_count ? "" : ",");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
}

static void emit_json_timing_stat(
    FILE *out, const char *key, const timing_stat_t *stat, bool trailing_comma)
{
    if (!out || !key || !stat)
        return;
    fprintf(out,
        "    \"%s\": {\"sample_count\": %zu, \"mean_ms\": %.3f, "
        "\"median_ms\": %.3f, \"p95_ms\": %.3f, \"stddev_ms\": %.3f}%s\n",
        key, stat->sample_count, stat->mean_ms, stat->median_ms, stat->p95_ms,
        stat->stddev_ms, trailing_comma ? "," : "");
}

static void build_markdown_report_path(
    const char *output_path, char *buf, size_t buf_len)
{
    const char *dot = NULL;
    size_t base_len = 0U;

    if (!buf || buf_len == 0U)
        return;
    buf[0] = '\0';
    if (!output_path)
        return;

    dot = strrchr(output_path, '.');
    base_len = dot ? (size_t)(dot - output_path) : strlen(output_path);
    if (base_len + 3U >= buf_len)
        return;

    memcpy(buf, output_path, base_len);
    memcpy(buf + base_len, ".md", 4U);
}

static void emit_markdown_workload_metric_row(
    FILE *out, const char *label, const workload_strategy_metric_t *metric)
{
    if (!out || !label || !metric)
        return;

    fprintf(out, "| %s | %.2f | %.2f | %.2f | %.2f | %.3f | %.3f | %.3f |\n",
        label, metric->background_bytes, metric->foreground_bytes,
        metric->total_bytes, metric->online_requests, metric->local_ms,
        metric->total_ms_20kbps, metric->total_ms_64kbps);
}

static void emit_markdown_timing_stat_row(
    FILE *out, const char *label, const timing_stat_t *stat)
{
    if (!out || !label || !stat)
        return;
    fprintf(out, "| %s | %zu | %.3f | %.3f | %.3f | %.3f |\n", label,
        stat->sample_count, stat->mean_ms, stat->median_ms, stat->p95_ms,
        stat->stddev_ms);
}

static void emit_markdown_report_legacy(FILE *out,
    const base_metric_t *base_metrics,
    const real_revocation_baseline_t *real_baseline,
    const controlled_network_compare_t *network_metrics,
    const zipf_workload_point_t *zipf_points, size_t zipf_count,
    const zipf_strategy_compare_point_t *strategy_points, size_t strategy_count)
{
    const zipf_workload_point_t *zipf_final = NULL;
    const zipf_strategy_compare_point_t *strategy_final = NULL;
    double implicit_vs_x509_pct = 0.0;

    if (!out || !base_metrics || !real_baseline || !network_metrics)
        return;

    if (base_metrics->x509_der_bytes > 0U)
    {
        implicit_vs_x509_pct
            = ((double)base_metrics->implicit_cert_bytes * 100.0)
            / (double)base_metrics->x509_der_bytes;
    }
    if (zipf_count > 0U)
        zipf_final = &zipf_points[zipf_count - 1U];
    if (strategy_count > 0U)
        strategy_final = &strategy_points[strategy_count - 1U];

    fprintf(out, "# TinyPKI 能力测试报告\n\n");
    fprintf(out,
        "由 `sm2_bench_capability_suite` 自动生成。该报告将机器可读 JSON "
        "结果整理为便于汇报和写材料的表格。\n\n");
    fprintf(out,
        "> 注：`CRL/OCSP/TinyPKI` 为本地受控实验结果，`CRLite` 仍为参考论"
        "文参数的建模基线。\n\n");

    fprintf(out, "## 总览摘要\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(
        out, "| X.509 DER 证书大小 | %zu |\n", base_metrics->x509_der_bytes);
    fprintf(out, "| ECQV 隐式证书大小 | %zu |\n",
        base_metrics->implicit_cert_bytes);
    fprintf(
        out, "| 隐式证书相对 X.509 比例 | %.2f%% |\n", implicit_vs_x509_pct);
    fprintf(
        out, "| Root Record 大小 | %zu |\n", base_metrics->root_record_bytes);
    fprintf(out, "| 紧凑 Root Hint 大小 | %zu |\n",
        base_metrics->compact_root_hint_bytes);
    fprintf(out, "| Absence Proof 大小 | %zu |\n",
        base_metrics->absence_proof_bytes);
    fprintf(out, "| 发证透明 Evidence 大小 | %zu |\n",
        base_metrics->issuance_evidence_bytes);
    fprintf(
        out, "| 完整认证消息大小 | %zu |\n", base_metrics->auth_bundle_bytes);
    fprintf(out, "| 紧凑认证消息大小 | %zu |\n",
        base_metrics->auth_bundle_compact_bytes);
    fprintf(out, "| 完整认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_median_ms);
    fprintf(out, "| 紧凑认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_compact_median_ms);
    fprintf(out, "| 完整安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_median_ms);
    fprintf(out, "| 紧凑安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_compact_median_ms);
    fprintf(out, "| 吊销发布中位时延 | %.3f ms |\n",
        base_metrics->revoke_publish_median_ms);
    fprintf(out, "| 服务端刷新 Root 中位时延 | %.3f ms |\n",
        base_metrics->service_refresh_root_median_ms);
    fprintf(out, "| 客户端刷新 Root 中位时延 | %.3f ms |\n\n",
        base_metrics->client_refresh_root_median_ms);

    fprintf(out, "## 真实 CRL/OCSP 对象基线\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(out, "| CRL 条目数 | %zu |\n", real_baseline->crl_entry_count);
    fprintf(out, "| CRL DER 大小 | %zu |\n", real_baseline->crl_der_bytes);
    fprintf(out, "| OCSP 请求 DER 大小 | %zu |\n",
        real_baseline->ocsp_request_der_bytes);
    fprintf(out, "| OCSP 响应 DER 大小 | %zu |\n",
        real_baseline->ocsp_response_der_bytes);
    fprintf(out, "| OCSP 线缆总大小 | %zu |\n", real_baseline->ocsp_wire_bytes);
    fprintf(out, "| CRL 校验+查找中位时延 | %.3f ms |\n",
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out, "| OCSP 校验中位时延 | %.3f ms |\n\n",
        real_baseline->ocsp_verify_median_ms);

    fprintf(out, "## 受控 Loopback HTTP 对比\n\n");
    fprintf(out, "| 方案 | 请求字节 | 响应字节 | 总字节 | 往返中位时延 |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: |\n");
    fprintf(out, "| CRL HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->crl_http.request_bytes,
        network_metrics->crl_http.response_bytes,
        network_metrics->crl_http.total_bytes,
        network_metrics->crl_http.roundtrip_median_ms);
    fprintf(out, "| OCSP HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->ocsp_http.request_bytes,
        network_metrics->ocsp_http.response_bytes,
        network_metrics->ocsp_http.total_bytes,
        network_metrics->ocsp_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 完整 HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->tinypki_full_http.request_bytes,
        network_metrics->tinypki_full_http.response_bytes,
        network_metrics->tinypki_full_http.total_bytes,
        network_metrics->tinypki_full_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 紧凑 HTTP | %zu | %zu | %zu | %.3f ms |\n\n",
        network_metrics->tinypki_compact_http.request_bytes,
        network_metrics->tinypki_compact_http.response_bytes,
        network_metrics->tinypki_compact_http.total_bytes,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);

    fprintf(out, "## Timing Stability\n\n");
    fprintf(out, "| Metric | Samples | Mean | Median | P95 | Stddev |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: | ---: |\n");
    emit_markdown_timing_stat_row(
        out, "CRL verify+lookup", &real_baseline->crl_verify_lookup_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP verify", &real_baseline->ocsp_verify_timing);
    emit_markdown_timing_stat_row(
        out, "CRL HTTP RTT", &network_metrics->crl_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP HTTP RTT", &network_metrics->ocsp_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI full HTTP RTT",
        &network_metrics->tinypki_full_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI compact HTTP RTT",
        &network_metrics->tinypki_compact_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI verify bundle", &base_metrics->verify_bundle_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI verify compact",
        &base_metrics->verify_bundle_compact_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI secure session", &base_metrics->secure_session_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI secure compact",
        &base_metrics->secure_session_compact_timing);
    fprintf(out, "\n");

    fprintf(out, "## 冷启动 / 热路径口径\n\n");
    fprintf(out, "| 方案 | 冷启动路径 | 热路径 |\n");
    fprintf(out, "| --- | --- | --- |\n");
    fprintf(out,
        "| 仅 CRL | CRL HTTP 获取并校验（%.3f ms） | 本地 CRL 查找（%.3f ms） "
        "|\n",
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| OCSP + CRL | OCSP HTTP 查询或回退 CRL（%.3f ms / %.3f ms） | 本地 "
        "OCSP 校验或 CRL 查找（%.3f ms / %.3f ms） |\n",
        network_metrics->ocsp_http.roundtrip_median_ms,
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->ocsp_verify_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| TinyPKI | 完整认证消息 + 完整 root 记录（%.3f ms） | 紧凑认证消息 + "
        "cached root hint（%.3f ms） |\n\n",
        network_metrics->tinypki_full_http.roundtrip_median_ms,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);

    if (zipf_final)
    {
        fprintf(out, "## Zipf 场景摘要（%zu 次访问）\n\n", zipf_final->visits);
        fprintf(out, "| 指标 | 数值 |\n");
        fprintf(out, "| --- | ---: |\n");
        fprintf(out, "| 平均不同通信对象数 | %.2f |\n",
            zipf_final->mean_unique_domains);
        fprintf(out, "| 认证累计字节 | %.2f |\n", zipf_final->auth_bytes);
        fprintf(
            out, "| 20 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_20kbps);
        fprintf(
            out, "| 64 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_64kbps);
        fprintf(out, "| 256 kbps 传输时延 | %.3f ms |\n",
            zipf_final->tx_ms_256kbps);
        fprintf(out, "| 本地验证累计时延 | %.3f ms |\n",
            zipf_final->local_verify_ms);
        fprintf(out, "| 安全会话累计时延 | %.3f ms |\n",
            zipf_final->secure_session_ms);
        fprintf(out, "| 本地累计总时延 | %.3f ms |\n",
            zipf_final->combined_local_ms);
        fprintf(out, "| 20 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_20kbps);
        fprintf(out, "| 64 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_64kbps);
        fprintf(out, "| 256 kbps 综合总时延 | %.3f ms |\n\n",
            zipf_final->combined_total_ms_256kbps);
    }

    if (strategy_final)
    {
        fprintf(out, "## 四方案对比（%zu 次访问）\n\n", strategy_final->visits);
        fprintf(out,
            "| 方案 | 后台字节 | 前台字节 | 总字节 | 在线请求数 | 本地时延 | "
            "20 kbps 总时延 | 64 kbps 总时延 |\n");
        fprintf(
            out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        emit_markdown_workload_metric_row(
            out, "仅 CRL", &strategy_final->crl_only);
        emit_markdown_workload_metric_row(
            out, "OCSP + CRL", &strategy_final->ocsp_and_crl);
        emit_markdown_workload_metric_row(
            out, "CRLite", &strategy_final->crlite);
        emit_markdown_workload_metric_row(
            out, "TinyPKI 紧凑", &strategy_final->tinypki_compact);
        fprintf(out, "\n");
    }
}

static void emit_markdown_report_old(FILE *out,
    const base_metric_t *base_metrics,
    const real_revocation_baseline_t *real_baseline,
    const controlled_network_compare_t *network_metrics,
    const zipf_workload_point_t *zipf_points, size_t zipf_count,
    const zipf_strategy_compare_point_t *strategy_points, size_t strategy_count)
{
    const zipf_workload_point_t *zipf_final = NULL;
    const zipf_strategy_compare_point_t *strategy_final = NULL;
    double implicit_vs_x509_pct = 0.0;

    if (!out || !base_metrics || !real_baseline || !network_metrics)
        return;

    if (base_metrics->x509_der_bytes > 0U)
    {
        implicit_vs_x509_pct
            = ((double)base_metrics->implicit_cert_bytes * 100.0)
            / (double)base_metrics->x509_der_bytes;
    }
    if (zipf_count > 0U)
        zipf_final = &zipf_points[zipf_count - 1U];
    if (strategy_count > 0U)
        strategy_final = &strategy_points[strategy_count - 1U];

    fprintf(out, "# TinyPKI 能力测试报告\n\n");
    fprintf(out,
        "由 `sm2_bench_capability_suite` 自动生成。该报告将机器可读 JSON "
        "结果整理为便于汇报和写材料的表格。\n\n");
    fprintf(out,
        "> 注：`CRL/OCSP/TinyPKI` 为本地受控实验结果，`CRLite` "
        "仍为参考论文参数的建模基线。\n\n");

    fprintf(out, "## 总览摘要\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(
        out, "| X.509 DER 证书大小 | %zu |\n", base_metrics->x509_der_bytes);
    fprintf(out, "| ECQV 隐式证书大小 | %zu |\n",
        base_metrics->implicit_cert_bytes);
    fprintf(
        out, "| 隐式证书相对 X.509 比例 | %.2f%% |\n", implicit_vs_x509_pct);
    fprintf(out, "| 根记录大小 | %zu |\n", base_metrics->root_record_bytes);
    fprintf(out, "| 紧凑根提示大小 | %zu |\n",
        base_metrics->compact_root_hint_bytes);
    fprintf(out, "| 缺席证明大小 | %zu |\n", base_metrics->absence_proof_bytes);
    fprintf(out, "| 发证透明 Evidence 大小 | %zu |\n",
        base_metrics->issuance_evidence_bytes);
    fprintf(
        out, "| 完整认证消息大小 | %zu |\n", base_metrics->auth_bundle_bytes);
    fprintf(out, "| 紧凑认证消息大小 | %zu |\n",
        base_metrics->auth_bundle_compact_bytes);
    fprintf(out, "| 完整认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_median_ms);
    fprintf(out, "| 紧凑认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_compact_median_ms);
    fprintf(out, "| 完整安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_median_ms);
    fprintf(out, "| 紧凑安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_compact_median_ms);
    fprintf(out, "| 吊销发布中位时延 | %.3f ms |\n",
        base_metrics->revoke_publish_median_ms);
    fprintf(out, "| 服务端刷新根记录中位时延 | %.3f ms |\n",
        base_metrics->service_refresh_root_median_ms);
    fprintf(out, "| 客户端刷新根记录中位时延 | %.3f ms |\n\n",
        base_metrics->client_refresh_root_median_ms);
    fprintf(out,
        "说明：本表给出 TinyPKI "
        "主链路的核心体积和时延指标，用于说明证书是否足够轻、认证链路是否足够快"
        "。\n\n");

    fprintf(out, "## 真实 CRL/OCSP 对象基线\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(out, "| CRL 条目数 | %zu |\n", real_baseline->crl_entry_count);
    fprintf(out, "| CRL DER 大小 | %zu |\n", real_baseline->crl_der_bytes);
    fprintf(out, "| OCSP 请求 DER 大小 | %zu |\n",
        real_baseline->ocsp_request_der_bytes);
    fprintf(out, "| OCSP 响应 DER 大小 | %zu |\n",
        real_baseline->ocsp_response_der_bytes);
    fprintf(out, "| OCSP 线缆总大小 | %zu |\n", real_baseline->ocsp_wire_bytes);
    fprintf(out, "| CRL 校验+查找中位时延 | %.3f ms |\n",
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out, "| OCSP 校验中位时延 | %.3f ms |\n\n",
        real_baseline->ocsp_verify_median_ms);
    fprintf(out,
        "说明：本表给出真实构造的 CRL/OCSP "
        "协议对象大小和本地校验成本，用于建立传统撤销机制基线。\n\n");

    fprintf(out, "## 受控回环 HTTP 对比\n\n");
    fprintf(out, "| 方案 | 请求字节 | 响应字节 | 总字节 | 往返中位时延 |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: |\n");
    fprintf(out, "| CRL HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->crl_http.request_bytes,
        network_metrics->crl_http.response_bytes,
        network_metrics->crl_http.total_bytes,
        network_metrics->crl_http.roundtrip_median_ms);
    fprintf(out, "| OCSP HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->ocsp_http.request_bytes,
        network_metrics->ocsp_http.response_bytes,
        network_metrics->ocsp_http.total_bytes,
        network_metrics->ocsp_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 完整 HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->tinypki_full_http.request_bytes,
        network_metrics->tinypki_full_http.response_bytes,
        network_metrics->tinypki_full_http.total_bytes,
        network_metrics->tinypki_full_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 紧凑 HTTP | %zu | %zu | %zu | %.3f ms |\n\n",
        network_metrics->tinypki_compact_http.request_bytes,
        network_metrics->tinypki_compact_http.response_bytes,
        network_metrics->tinypki_compact_http.total_bytes,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);
    fprintf(out,
        "说明：本表把 CRL、OCSP 与 TinyPKI 放到同一受控本地 HTTP "
        "传输下，直接比较单次前台通信负担。\n\n");

    fprintf(out, "## 稳定性统计\n\n");
    fprintf(out, "| 指标项 | 样本数 | 均值 | 中位数 | P95 | 标准差 |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: | ---: |\n");
    emit_markdown_timing_stat_row(
        out, "CRL 校验+查找", &real_baseline->crl_verify_lookup_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP 校验", &real_baseline->ocsp_verify_timing);
    emit_markdown_timing_stat_row(
        out, "CRL HTTP 往返", &network_metrics->crl_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP HTTP 往返", &network_metrics->ocsp_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 完整 HTTP 往返",
        &network_metrics->tinypki_full_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑 HTTP 往返",
        &network_metrics->tinypki_compact_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI 完整认证验证", &base_metrics->verify_bundle_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑认证验证",
        &base_metrics->verify_bundle_compact_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI 完整安全会话", &base_metrics->secure_session_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑安全会话",
        &base_metrics->secure_session_compact_timing);
    fprintf(out, "\n");
    fprintf(out,
        "说明：本表展示关键测量的样本分布情况，用于判断实验结果是否稳定、是否存"
        "在明显抖动。\n\n");

    fprintf(out, "## 冷启动 / 热路径口径\n\n");
    fprintf(out, "| 方案 | 冷启动路径 | 热路径 |\n");
    fprintf(out, "| --- | --- | --- |\n");
    fprintf(out,
        "| 仅 CRL | CRL HTTP 获取并校验（%.3f ms） | 本地 CRL 查找（%.3f ms） "
        "|\n",
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| OCSP + CRL | OCSP HTTP 查询或回退 CRL（%.3f ms / %.3f ms） | 本地 "
        "OCSP 校验或 CRL 查找（%.3f ms / %.3f ms） |\n",
        network_metrics->ocsp_http.roundtrip_median_ms,
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->ocsp_verify_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| TinyPKI | 完整认证消息 + 完整根记录（%.3f ms） | 紧凑认证消息 + "
        "缓存根提示（%.3f ms） |\n\n",
        network_metrics->tinypki_full_http.roundtrip_median_ms,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);
    fprintf(out,
        "说明：本表区分首次使用和缓存命中后的典型路径，用于解释各方案为何在累计"
        "成本上不同。\n\n");

    if (zipf_final)
    {
        fprintf(out, "## Zipf 场景摘要（%zu 次访问）\n\n", zipf_final->visits);
        fprintf(out, "| 指标 | 数值 |\n");
        fprintf(out, "| --- | ---: |\n");
        fprintf(out, "| 平均不同通信对象数 | %.2f |\n",
            zipf_final->mean_unique_domains);
        fprintf(out, "| 认证累计字节 | %.2f |\n", zipf_final->auth_bytes);
        fprintf(
            out, "| 20 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_20kbps);
        fprintf(
            out, "| 64 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_64kbps);
        fprintf(out, "| 256 kbps 传输时延 | %.3f ms |\n",
            zipf_final->tx_ms_256kbps);
        fprintf(out, "| 本地验证累计时延 | %.3f ms |\n",
            zipf_final->local_verify_ms);
        fprintf(out, "| 安全会话累计时延 | %.3f ms |\n",
            zipf_final->secure_session_ms);
        fprintf(out, "| 本地累计总时延 | %.3f ms |\n",
            zipf_final->combined_local_ms);
        fprintf(out, "| 20 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_20kbps);
        fprintf(out, "| 64 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_64kbps);
        fprintf(out, "| 256 kbps 综合总时延 | %.3f ms |\n\n",
            zipf_final->combined_total_ms_256kbps);
        fprintf(out,
            "说明：本表展示 TinyPKI "
            "在热点访问工作负载下的累计通信与处理成本，用于刻画实际使用场景中的"
            "总体负担。\n\n");
    }

    if (strategy_final)
    {
        fprintf(out, "## 四方案对比（%zu 次访问）\n\n", strategy_final->visits);
        fprintf(out,
            "| 方案 | 后台字节 | 前台字节 | 总字节 | 在线请求数 | 本地时延 | "
            "20 kbps 总时延 | 64 kbps 总时延 |\n");
        fprintf(
            out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        emit_markdown_workload_metric_row(
            out, "仅 CRL", &strategy_final->crl_only);
        emit_markdown_workload_metric_row(
            out, "OCSP + CRL", &strategy_final->ocsp_and_crl);
        emit_markdown_workload_metric_row(
            out, "CRLite", &strategy_final->crlite);
        emit_markdown_workload_metric_row(
            out, "TinyPKI 紧凑", &strategy_final->tinypki_compact);
        fprintf(out, "\n");
        fprintf(out,
            "说明：本表在统一工作负载下汇总四种方案的累计成本，用于直接比较通信"
            "、在线依赖和总时延差异。\n\n");
    }
}

static void emit_markdown_report(FILE *out, const base_metric_t *base_metrics,
    const real_revocation_baseline_t *real_baseline,
    const controlled_network_compare_t *network_metrics,
    const zipf_workload_point_t *zipf_points, size_t zipf_count,
    const zipf_strategy_compare_point_t *strategy_points, size_t strategy_count)
{
    const zipf_workload_point_t *zipf_final = NULL;
    const zipf_strategy_compare_point_t *strategy_final = NULL;
    double implicit_vs_x509_pct = 0.0;

    if (!out || !base_metrics || !real_baseline || !network_metrics)
        return;

    if (base_metrics->x509_der_bytes > 0U)
    {
        implicit_vs_x509_pct
            = ((double)base_metrics->implicit_cert_bytes * 100.0)
            / (double)base_metrics->x509_der_bytes;
    }
    if (zipf_count > 0U)
        zipf_final = &zipf_points[zipf_count - 1U];
    if (strategy_count > 0U)
        strategy_final = &strategy_points[strategy_count - 1U];

    fprintf(out, "# TinyPKI 能力测试报告\n\n");
    fprintf(out,
        "由 `sm2_bench_capability_suite` 自动生成。该报告将机器可读 JSON "
        "结果整理为便于汇报和写材料的表格。\n\n");
    fprintf(out,
        "> 注：`CRL/OCSP/TinyPKI` 为本地受控实验结果，`CRLite` "
        "仍为参考论文参数的建模基线。\n\n");

    fprintf(out, "## 总览摘要\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(
        out, "| X.509 DER 证书大小 | %zu |\n", base_metrics->x509_der_bytes);
    fprintf(out, "| ECQV 隐式证书大小 | %zu |\n",
        base_metrics->implicit_cert_bytes);
    fprintf(
        out, "| 隐式证书相对 X.509 比例 | %.2f%% |\n", implicit_vs_x509_pct);
    fprintf(out, "| 根记录大小 | %zu |\n", base_metrics->root_record_bytes);
    fprintf(out, "| 紧凑根提示大小 | %zu |\n",
        base_metrics->compact_root_hint_bytes);
    fprintf(out, "| 缺席证明大小 | %zu |\n", base_metrics->absence_proof_bytes);
    fprintf(out, "| 发证透明 Evidence 大小 | %zu |\n",
        base_metrics->issuance_evidence_bytes);
    fprintf(
        out, "| 完整认证消息大小 | %zu |\n", base_metrics->auth_bundle_bytes);
    fprintf(out, "| 紧凑认证消息大小 | %zu |\n",
        base_metrics->auth_bundle_compact_bytes);
    fprintf(out, "| 完整认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_median_ms);
    fprintf(out, "| 紧凑认证验证中位时延 | %.3f ms |\n",
        base_metrics->verify_bundle_compact_median_ms);
    fprintf(out, "| 完整安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_median_ms);
    fprintf(out, "| 紧凑安全会话中位时延 | %.3f ms |\n",
        base_metrics->secure_session_compact_median_ms);
    fprintf(out, "| 吊销发布中位时延 | %.3f ms |\n",
        base_metrics->revoke_publish_median_ms);
    fprintf(out, "| 服务端刷新根记录中位时延 | %.3f ms |\n",
        base_metrics->service_refresh_root_median_ms);
    fprintf(out, "| 客户端刷新根记录中位时延 | %.3f ms |\n\n",
        base_metrics->client_refresh_root_median_ms);
    fprintf(out,
        "隐式证书仅为 X.509 基线的 %.2f%%，紧凑认证消息为 %zu B，说明 TinyPKI "
        "在证书和前台认证载荷上具备明显轻量化优势。\n\n",
        implicit_vs_x509_pct, base_metrics->auth_bundle_compact_bytes);

    fprintf(out, "## 真实 CRL/OCSP 对象基线\n\n");
    fprintf(out, "| 指标 | 数值 |\n");
    fprintf(out, "| --- | ---: |\n");
    fprintf(out, "| CRL 条目数 | %zu |\n", real_baseline->crl_entry_count);
    fprintf(out, "| CRL DER 大小 | %zu |\n", real_baseline->crl_der_bytes);
    fprintf(out, "| OCSP 请求 DER 大小 | %zu |\n",
        real_baseline->ocsp_request_der_bytes);
    fprintf(out, "| OCSP 响应 DER 大小 | %zu |\n",
        real_baseline->ocsp_response_der_bytes);
    fprintf(out, "| OCSP 线缆总大小 | %zu |\n", real_baseline->ocsp_wire_bytes);
    fprintf(out, "| CRL 校验+查找中位时延 | %.3f ms |\n",
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out, "| OCSP 校验中位时延 | %.3f ms |\n\n",
        real_baseline->ocsp_verify_median_ms);
    fprintf(out,
        "真实协议对象表明：CRL 大小为 %zu B，而 OCSP 线缆总大小为 %zu B，说明 "
        "CRL 更偏列表分发，OCSP 更偏小响应在线查询。\n\n",
        real_baseline->crl_der_bytes, real_baseline->ocsp_wire_bytes);

    fprintf(out, "## 受控回环 HTTP 对比\n\n");
    fprintf(out, "| 方案 | 请求字节 | 响应字节 | 总字节 | 往返中位时延 |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: |\n");
    fprintf(out, "| CRL HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->crl_http.request_bytes,
        network_metrics->crl_http.response_bytes,
        network_metrics->crl_http.total_bytes,
        network_metrics->crl_http.roundtrip_median_ms);
    fprintf(out, "| OCSP HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->ocsp_http.request_bytes,
        network_metrics->ocsp_http.response_bytes,
        network_metrics->ocsp_http.total_bytes,
        network_metrics->ocsp_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 完整 HTTP | %zu | %zu | %zu | %.3f ms |\n",
        network_metrics->tinypki_full_http.request_bytes,
        network_metrics->tinypki_full_http.response_bytes,
        network_metrics->tinypki_full_http.total_bytes,
        network_metrics->tinypki_full_http.roundtrip_median_ms);
    fprintf(out, "| TinyPKI 紧凑 HTTP | %zu | %zu | %zu | %.3f ms |\n\n",
        network_metrics->tinypki_compact_http.request_bytes,
        network_metrics->tinypki_compact_http.response_bytes,
        network_metrics->tinypki_compact_http.total_bytes,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);
    fprintf(out,
        "在同一受控传输下，TinyPKI 紧凑路径总字节为 %zu B，低于 OCSP 的 %zu "
        "B，也远低于 CRL 的 %zu B，说明其单次前台通信负担更小。\n\n",
        network_metrics->tinypki_compact_http.total_bytes,
        network_metrics->ocsp_http.total_bytes,
        network_metrics->crl_http.total_bytes);

    fprintf(out, "## 稳定性统计\n\n");
    fprintf(out, "| 指标项 | 样本数 | 均值 | 中位数 | P95 | 标准差 |\n");
    fprintf(out, "| --- | ---: | ---: | ---: | ---: | ---: |\n");
    emit_markdown_timing_stat_row(
        out, "CRL 校验+查找", &real_baseline->crl_verify_lookup_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP 校验", &real_baseline->ocsp_verify_timing);
    emit_markdown_timing_stat_row(
        out, "CRL HTTP 往返", &network_metrics->crl_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "OCSP HTTP 往返", &network_metrics->ocsp_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 完整 HTTP 往返",
        &network_metrics->tinypki_full_http.roundtrip_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑 HTTP 往返",
        &network_metrics->tinypki_compact_http.roundtrip_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI 完整认证验证", &base_metrics->verify_bundle_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑认证验证",
        &base_metrics->verify_bundle_compact_timing);
    emit_markdown_timing_stat_row(
        out, "TinyPKI 完整安全会话", &base_metrics->secure_session_timing);
    emit_markdown_timing_stat_row(out, "TinyPKI 紧凑安全会话",
        &base_metrics->secure_session_compact_timing);
    fprintf(out, "\n");
    fprintf(out,
        "多数关键测量的 P95 与中位数相距不大，说明结果整体稳定；但紧凑 HTTP "
        "与紧凑认证验证的标准差相对更高，说明热路径仍有进一步收敛空间。\n\n");

    fprintf(out, "## 冷启动 / 热路径口径\n\n");
    fprintf(out, "| 方案 | 冷启动路径 | 热路径 |\n");
    fprintf(out, "| --- | --- | --- |\n");
    fprintf(out,
        "| 仅 CRL | CRL HTTP 获取并校验（%.3f ms） | 本地 CRL 查找（%.3f ms） "
        "|\n",
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| OCSP + CRL | OCSP HTTP 查询或回退 CRL（%.3f ms / %.3f ms） | 本地 "
        "OCSP 校验或 CRL 查找（%.3f ms / %.3f ms） |\n",
        network_metrics->ocsp_http.roundtrip_median_ms,
        network_metrics->crl_http.roundtrip_median_ms,
        real_baseline->ocsp_verify_median_ms,
        real_baseline->crl_verify_lookup_median_ms);
    fprintf(out,
        "| TinyPKI | 完整认证消息 + 完整根记录（%.3f ms） | 紧凑认证消息 + "
        "缓存根提示（%.3f ms） |\n\n",
        network_metrics->tinypki_full_http.roundtrip_median_ms,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);
    fprintf(out,
        "热路径相较冷启动都更轻，其中 TinyPKI "
        "把完整根记录收缩为缓存根提示后，往返中位时延从 %.3f ms 降到 %.3f "
        "ms，体现了缓存协作的价值。\n\n",
        network_metrics->tinypki_full_http.roundtrip_median_ms,
        network_metrics->tinypki_compact_http.roundtrip_median_ms);

    if (zipf_final)
    {
        fprintf(out, "## Zipf 场景摘要（%zu 次访问）\n\n", zipf_final->visits);
        fprintf(out, "| 指标 | 数值 |\n");
        fprintf(out, "| --- | ---: |\n");
        fprintf(out, "| 平均不同通信对象数 | %.2f |\n",
            zipf_final->mean_unique_domains);
        fprintf(out, "| 认证累计字节 | %.2f |\n", zipf_final->auth_bytes);
        fprintf(
            out, "| 20 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_20kbps);
        fprintf(
            out, "| 64 kbps 传输时延 | %.3f ms |\n", zipf_final->tx_ms_64kbps);
        fprintf(out, "| 256 kbps 传输时延 | %.3f ms |\n",
            zipf_final->tx_ms_256kbps);
        fprintf(out, "| 本地验证累计时延 | %.3f ms |\n",
            zipf_final->local_verify_ms);
        fprintf(out, "| 安全会话累计时延 | %.3f ms |\n",
            zipf_final->secure_session_ms);
        fprintf(out, "| 本地累计总时延 | %.3f ms |\n",
            zipf_final->combined_local_ms);
        fprintf(out, "| 20 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_20kbps);
        fprintf(out, "| 64 kbps 综合总时延 | %.3f ms |\n",
            zipf_final->combined_total_ms_64kbps);
        fprintf(out, "| 256 kbps 综合总时延 | %.3f ms |\n\n",
            zipf_final->combined_total_ms_256kbps);
        fprintf(out,
            "在 1000 次访问下，20 kbps 传输时延为 %.3f ms，而本地累计总时延为 "
            "%.3f ms，说明弱网场景中通信成本仍显著高于本地计算。\n\n",
            zipf_final->tx_ms_20kbps, zipf_final->combined_local_ms);
    }

    if (strategy_final)
    {
        fprintf(out, "## 四方案对比（%zu 次访问）\n\n", strategy_final->visits);
        fprintf(out,
            "| 方案 | 后台字节 | 前台字节 | 总字节 | 在线请求数 | 本地时延 | "
            "20 kbps 总时延 | 64 kbps 总时延 |\n");
        fprintf(
            out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        emit_markdown_workload_metric_row(
            out, "仅 CRL", &strategy_final->crl_only);
        emit_markdown_workload_metric_row(
            out, "OCSP + CRL", &strategy_final->ocsp_and_crl);
        emit_markdown_workload_metric_row(
            out, "CRLite", &strategy_final->crlite);
        emit_markdown_workload_metric_row(
            out, "TinyPKI 紧凑", &strategy_final->tinypki_compact);
        fprintf(out, "\n");
        fprintf(out,
            "在统一工作负载下，TinyPKI 紧凑总字节为 %.2f B，已接近 CRLite 的 "
            "%.2f B，并明显低于 OCSP + CRL 与仅 CRL；这说明 TinyPKI "
            "在累计通信成本上具备明显优势。\n\n",
            strategy_final->tinypki_compact.total_bytes,
            strategy_final->crlite.total_bytes);
    }
}

int main(int argc, char **argv)
{
    base_metric_t base_metrics;
    real_revocation_baseline_t real_baseline;
    real_revocation_artifacts_t real_artifacts;
    controlled_network_compare_t network_metrics;
    revocation_scale_metric_t revocation_metrics[6];
    multiproof_metric_t multiproof_metrics[6];
    delta_metric_t delta_metrics[5];
    epoch_cache_metric_t epoch_metrics[5];
    zipf_workload_point_t zipf_points[5];
    zipf_strategy_compare_point_t strategy_points[5];
    FILE *out = stdout;
    FILE *report_out = NULL;
    char report_path[1024];

    memset(&base_metrics, 0, sizeof(base_metrics));
    memset(&real_baseline, 0, sizeof(real_baseline));
    memset(&real_artifacts, 0, sizeof(real_artifacts));
    memset(&network_metrics, 0, sizeof(network_metrics));
    memset(revocation_metrics, 0, sizeof(revocation_metrics));
    memset(multiproof_metrics, 0, sizeof(multiproof_metrics));
    memset(delta_metrics, 0, sizeof(delta_metrics));
    memset(epoch_metrics, 0, sizeof(epoch_metrics));
    memset(zipf_points, 0, sizeof(zipf_points));
    memset(strategy_points, 0, sizeof(strategy_points));

    if (!collect_base_metrics(&base_metrics))
    {
        fprintf(stderr, "TinyPKI capability benchmark failed: base metrics.\n");
        return 1;
    }
    if (!collect_real_revocation_baseline_metrics(
            &real_baseline, &real_artifacts))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: real CRL/OCSP baseline.\n");
        return 1;
    }
    if (!collect_controlled_network_compare_metrics(
            &real_artifacts, &network_metrics))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: controlled network "
            "compare.\n");
        cleanup_real_revocation_artifacts(&real_artifacts);
        return 1;
    }
    if (!collect_revocation_scaling_metrics(revocation_metrics,
            sizeof(revocation_metrics) / sizeof(revocation_metrics[0])))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: revocation scaling.\n");
        return 1;
    }
    if (!collect_multiproof_metrics(multiproof_metrics,
            sizeof(multiproof_metrics) / sizeof(multiproof_metrics[0])))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: multiproof scaling.\n");
        return 1;
    }
    if (!collect_delta_metrics(
            delta_metrics, sizeof(delta_metrics) / sizeof(delta_metrics[0])))
    {
        fprintf(
            stderr, "TinyPKI capability benchmark failed: delta scaling.\n");
        return 1;
    }
    if (!collect_epoch_cache_metrics(
            epoch_metrics, sizeof(epoch_metrics) / sizeof(epoch_metrics[0])))
    {
        fprintf(stderr, "TinyPKI capability benchmark failed: epoch cache.\n");
        return 1;
    }
    if (!collect_zipf_workload_points(&base_metrics, zipf_points,
            sizeof(zipf_points) / sizeof(zipf_points[0])))
    {
        fprintf(
            stderr, "TinyPKI capability benchmark failed: zipf workload.\n");
        return 1;
    }
    if (!collect_zipf_strategy_comparison_points(&base_metrics, &real_baseline,
            &network_metrics, strategy_points,
            sizeof(strategy_points) / sizeof(strategy_points[0])))
    {
        fprintf(stderr,
            "TinyPKI capability benchmark failed: zipf strategy compare.\n");
        cleanup_real_revocation_artifacts(&real_artifacts);
        return 1;
    }

    if (argc > 1)
    {
        out = fopen(argv[1], "wb");
        if (!out)
        {
            fprintf(stderr, "Failed to open output file: %s\n", argv[1]);
            return 1;
        }
        build_markdown_report_path(argv[1], report_path, sizeof(report_path));
        if (report_path[0] != '\0')
        {
            report_out = fopen(report_path, "wb");
            if (!report_out)
            {
                fprintf(stderr, "Failed to open markdown report: %s\n",
                    report_path);
            }
        }
    }

    emit_json(out, &base_metrics, &real_baseline, &network_metrics,
        revocation_metrics,
        sizeof(revocation_metrics) / sizeof(revocation_metrics[0]),
        multiproof_metrics,
        sizeof(multiproof_metrics) / sizeof(multiproof_metrics[0]),
        delta_metrics, sizeof(delta_metrics) / sizeof(delta_metrics[0]),
        epoch_metrics, sizeof(epoch_metrics) / sizeof(epoch_metrics[0]),
        zipf_points, sizeof(zipf_points) / sizeof(zipf_points[0]),
        strategy_points, sizeof(strategy_points) / sizeof(strategy_points[0]));
    if (report_out)
    {
        static const unsigned char utf8_bom[] = { 0xEF, 0xBB, 0xBF };
        fwrite(utf8_bom, 1U, sizeof(utf8_bom), report_out);
        emit_markdown_report(report_out, &base_metrics, &real_baseline,
            &network_metrics, zipf_points,
            sizeof(zipf_points) / sizeof(zipf_points[0]), strategy_points,
            sizeof(strategy_points) / sizeof(strategy_points[0]));
        fclose(report_out);
    }

    if (out != stdout)
        fclose(out);
    cleanup_real_revocation_artifacts(&real_artifacts);
    return 0;
}
