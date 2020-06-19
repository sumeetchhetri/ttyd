#include <libwebsockets.h>
#include <openssl/ssl.h>
#include <string.h>
#include <zlib.h>
#include <stdlib.h>
#include <errno.h> 
#include <netdb.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h>
#include <stdio.h>
#include <malloc.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "html.h"
#include "server.h"
#include "utils.h"

#if LWS_LIBRARY_VERSION_MAJOR < 2
#define HTTP_STATUS_FOUND 302
#endif

enum { AUTH_OK, AUTH_FAIL, AUTH_ERROR };

static char *html_cache = NULL;
static size_t html_cache_len = 0;

static int auth_error(struct lws *wsi, struct pss_http *pss, int basic) {
  char *body = strdup("401 Unauthorized\n");
  size_t n = strlen(body);

  unsigned char buffer[1024 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  if (lws_add_http_header_status(wsi, HTTP_STATUS_UNAUTHORIZED, &p, end) ||
      (basic==1 && lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
                                   (unsigned char *)"Basic realm=\"ttyd\"", 18, &p, end)==0) ||
      lws_add_http_header_content_length(wsi, n, &p, end) ||
      lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return AUTH_ERROR;

  pss->buffer = pss->ptr = body;
  pss->len = n;
  lws_callback_on_writable(wsi);

  return AUTH_FAIL;
}

static bool url_auth_validate(struct lws *wsi) {
  int sockfd, numbytes;  
  char buf[2048];
  struct hostent *he;
  struct sockaddr_in their_addr; /* connector's address information */

  if ((he=gethostbyname(server->auth_url.host)) == NULL) {  /* get the host info */
    herror("gethostbyname");
    return false;
  }

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return false;
  }

  their_addr.sin_family = AF_INET;      /* host byte order */
  their_addr.sin_port = htons(server->auth_url.port);    /* short, network byte order */
  their_addr.sin_addr = *((struct in_addr *)he->h_addr);
  bzero(&(their_addr.sin_zero), 8);     /* zero the rest of the struct */

  if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
    perror("connect");
    return false;
  }

  char req[2048];
  strcpy(&req[0], "GET /");
  int pos = 5;
  if(server->auth_url.path!=NULL) {
    strcpy(&req[pos], server->auth_url.path);
    pos += strlen(server->auth_url.path);
  }
  if(server->auth_url.query!=NULL) {
    strcpy(&req[pos], "?");
    pos += 1;
    strcpy(&req[pos], server->auth_url.query);
    pos += strlen(server->auth_url.query);
  }
  char lwq[200];
  int lwc = 0;
  bool lws = false;
  while(lws_hdr_copy_fragment(wsi, lwq, 200, WSI_TOKEN_HTTP_URI_ARGS, lwc++)!=-1) {
    if(!lws) {
      lws = true;
      if(server->auth_url.query==NULL) {
        strcpy(&req[pos], "?");
        pos += 1;
      } else {
        strcpy(&req[pos], "&");
        pos += 1;
      }
    }

    strcpy(&req[pos], lwq);
    pos += strlen(lwq);
    strcpy(&req[pos], "&");
    pos += 1;
  }

  strcpy(&req[pos], " HTTP/1.1\r\nUser-Agent: program\r\nOrigin: ");
  pos += 40;
  strcpy(&req[pos], server->auth_url.scheme);
  pos += strlen(server->auth_url.scheme);
  strcpy(&req[pos], "://");
  pos += 3;
  strcpy(&req[pos], server->auth_url.host);
  pos += strlen(server->auth_url.host);
  if((strcmp(server->auth_url.scheme, "http")==0 && server->auth_url.port != 80) || 
      (strcmp(server->auth_url.scheme, "https")==0 && server->auth_url.port != 443)) {
    char port_s[5];
    snprintf(port_s, 5, "%d", server->auth_url.port);
    strcpy(&req[pos], port_s);
    pos += strlen(port_s);
  }
  strcpy(&req[pos], "\r\n");
  pos += 2;
  strcpy(&req[pos], "Host: ");
  pos += 6;
  strcpy(&req[pos], server->auth_url.host);
  pos += strlen(server->auth_url.host);
  strcpy(&req[pos], "\r\n\r\n");
  pos += 4;

  printf("%s", req);

  if(strcmp(server->auth_url.scheme, "https")==0) {
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
  #if defined(LWS_HAVE_TLS_CLIENT_METHOD)
    const SSL_METHOD *method = TLS_client_method();  /* Create new client-method instance */
  #elif defined(LWS_HAVE_TLSV1_2_CLIENT_METHOD)
    const SSL_METHOD *method = (SSL_METHOD *)TLSv1_2_client_method();
  #else
    const SSL_METHOD *method = (SSL_METHOD *)SSLv23_client_method();
  #endif
    
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        return false;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if ( SSL_connect(ssl) == -1 ) {
      ERR_print_errors_fp(stderr);
      close(sockfd);
      SSL_CTX_free(ctx);
      return false;
    }

    if(SSL_write(ssl, req, pos)<=0) {
      perror("SSL_write");
      SSL_free(ssl);
      close(sockfd);
      SSL_CTX_free(ctx);
      return false;
    }
    if ((numbytes = SSL_read(ssl, buf, 2048))<=0) {
      perror("SSL_read");
      SSL_free(ssl);
      close(sockfd);
      SSL_CTX_free(ctx);
      return false;
    }

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
  } else {
    if (send(sockfd, req, pos, 0) == -1){
      perror("send");
      close(sockfd);
      return false;
    }

    if ((numbytes=recv(sockfd, buf, 2048, 0)) == -1) {
      perror("recv");
      close(sockfd);
      return false;
    }
    close(sockfd);
  }
  
  if(strstr(buf, "HTTP/1.1 200")!=NULL) {
    return true;
  }
  return false;
}

static int check_auth(struct lws *wsi, struct pss_http *pss) {
  if(server->auth_url_str!=NULL && strlen(server->auth_url_str)>0) {
    if(url_auth_validate(wsi)) {
      return AUTH_OK;
    }
    return auth_error(wsi, pss, 0);
  }

  if (server->credential == NULL && !server->force_auth) return AUTH_OK;
  else if(server->force_auth && server->credential == NULL) return auth_error(wsi, pss, 1);

  int hdr_length = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
  char buf[hdr_length + 1];
  int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_AUTHORIZATION);
  if (len > 0) {
    // extract base64 text from authorization header
    char *ptr = &buf[0];
    char *token, *b64_text = NULL;
    int i = 1;
    while ((token = strsep(&ptr, " ")) != NULL) {
      if (strlen(token) == 0) continue;
      if (i++ == 2) {
        b64_text = token;
        break;
      }
    }
    if (b64_text != NULL && !strcmp(b64_text, server->credential)) return AUTH_OK;
  }

  return auth_error(wsi, pss, 1);
}

static bool accept_gzip(struct lws *wsi) {
  int hdr_length = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_ACCEPT_ENCODING);
  char buf[hdr_length + 1];
  int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_ACCEPT_ENCODING);
  return len > 0 && strstr(buf, "gzip") != NULL;
}

static bool uncompress_html(char **output, size_t *output_len) {
  if (html_cache == NULL || html_cache_len == 0) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 16 + 15) != Z_OK) return false;

    html_cache_len = index_html_size;
    html_cache = xmalloc(html_cache_len);

    stream.avail_in = index_html_len;
    stream.avail_out = html_cache_len;
    stream.next_in = (void *)index_html;
    stream.next_out = (void *)html_cache;

    int ret = inflate(&stream, Z_SYNC_FLUSH);
    inflateEnd(&stream);
    if (ret != Z_STREAM_END) {
      free(html_cache);
      html_cache = NULL;
      html_cache_len = 0;
      return false;
    }
  }

  *output = html_cache;
  *output_len = html_cache_len;

  return true;
}

static void pss_buffer_free(struct pss_http *pss) {
  if (pss->buffer != (char *)index_html && pss->buffer != html_cache) free(pss->buffer);
}

static void access_log(struct lws *wsi, const char *path) {
  char rip[50];

#if LWS_LIBRARY_VERSION_NUMBER >= 2004000
  lws_get_peer_simple(lws_get_network_wsi(wsi), rip, sizeof(rip));
#else
  char name[100];
  lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name, sizeof(name), rip, sizeof(rip));
#endif
  lwsl_notice("HTTP %s - %s\n", path, rip);
}

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in,
                  size_t len) {
  struct pss_http *pss = (struct pss_http *)user;
  unsigned char buffer[4096 + LWS_PRE], *p, *end;
  char buf[256];
  bool done = false;

  switch (reason) {
    case LWS_CALLBACK_HTTP:
      access_log(wsi, (const char *)in);
      snprintf(pss->path, sizeof(pss->path), "%s", (const char *)in);
      switch (check_auth(wsi, pss)) {
        case AUTH_OK:
          break;
        case AUTH_FAIL:
          return 0;
        case AUTH_ERROR:
        default:
          return 1;
      }

      p = buffer + LWS_PRE;
      end = p + sizeof(buffer) - LWS_PRE;

      if (strcmp(pss->path, endpoints.token) == 0) {
        const char *credential = server->credential != NULL ? server->credential : "";
        size_t n = sprintf(buf, "{\"token\": \"%s\"}", credential);
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                         (unsigned char *)"application/json;charset=utf-8", 30, &p,
                                         end) ||
            lws_add_http_header_content_length(wsi, (unsigned long)n, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

        pss->buffer = pss->ptr = strdup(buf);
        pss->len = n;
        lws_callback_on_writable(wsi);
        break;
      }

      // redirects `/base-path` to `/base-path/`
      if (strcmp(pss->path, endpoints.parent) == 0) {
        if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION,
                                         (unsigned char *)endpoints.index,
                                         (int)strlen(endpoints.index), &p, end) ||
            lws_add_http_header_content_length(wsi, 0, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;
        goto try_to_reuse;
      }

      if (strcmp(pss->path, endpoints.index) != 0) {
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
        goto try_to_reuse;
      }

      const char *content_type = "text/html";
      if (server->index != NULL) {
        int n = lws_serve_http_file(wsi, server->index, content_type, NULL, 0);
        if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) return 1;
      } else {
        char *output = (char *)index_html;
        size_t output_len = index_html_len;
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                         (const unsigned char *)content_type, 9, &p, end))
          return 1;
#ifdef LWS_WITH_HTTP_STREAM_COMPRESSION
        if (!uncompress_html(&output, &output_len)) return 1;
#else
        if (accept_gzip(wsi)) {
          if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING,
                                           (unsigned char *)"gzip", 4, &p, end))
            return 1;
        } else {
          if (!uncompress_html(&output, &output_len)) return 1;
        }
#endif

        if (lws_add_http_header_content_length(wsi, (unsigned long)output_len, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

#if LWS_LIBRARY_VERSION_MAJOR < 2
        if (lws_write_http(wsi, output, output_len) < 0) return 1;
        goto try_to_reuse;
#else
        pss->buffer = pss->ptr = output;
        pss->len = output_len;
        lws_callback_on_writable(wsi);
#endif
      }
      break;

    case LWS_CALLBACK_HTTP_WRITEABLE:
      if (!pss->buffer || pss->len <= 0) {
        goto try_to_reuse;
      }

      do {
        int n = sizeof(buffer) - LWS_PRE;
        int m = lws_get_peer_write_allowance(wsi);
        if (m == 0) {
          lws_callback_on_writable(wsi);
          return 0;
        } else if (m != -1 && m < n) {
          n = m;
        }
        if (pss->ptr + n > pss->buffer + pss->len) {
          n = (int)(pss->len - (pss->ptr - pss->buffer));
          done = true;
        }
        memcpy(buffer + LWS_PRE, pss->ptr, n);
        pss->ptr += n;
        if (lws_write_http(wsi, buffer + LWS_PRE, (size_t)n) < n) {
          pss_buffer_free(pss);
          return -1;
        }
      } while (!lws_send_pipe_choked(wsi) && !done);

      if (!done && pss->ptr < pss->buffer + pss->len) {
        lws_callback_on_writable(wsi);
        break;
      }

      pss_buffer_free(pss);
      goto try_to_reuse;

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
      goto try_to_reuse;

    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
      if (!len || (SSL_get_verify_result((SSL *)in) != X509_V_OK)) {
        int err = X509_STORE_CTX_get_error((X509_STORE_CTX *)user);
        int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *)user);
        const char *msg = X509_verify_cert_error_string(err);
        lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
        return 1;
      }
      break;
    default:
      break;
  }

  return 0;

  /* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
  if (lws_http_transaction_completed(wsi)) return -1;

  return 0;
}
