/* 
 *  rocks/crypt-openssl.c
 *
 *  Cryptography for reliable sockets over the OpenSSL API.
 *  See www.openssl.org.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "rs.h"
#include "log.h"

#define MAX_KEY_LEN     1024     /* Maximum size of all key buffers */
#define MSGLEN            32     /* Bytes in authentication challenge */ 
#define BUFLEN           128     /* Maximum buffer size for encryption ops */
#define CIPHER (EVP_bf_ecb())    /* OpenSSL cipher selector */

/* Shared Diffie-Hellman key exchange parameters. */
static const char *P = "DC04EB6EB146437F17F6422B78DE6F7B"; /* 128-bit prime */
static const char *G = "02";
/* FIXME: Make a per-rock copy of this? */
static DH *DH_PARAM; /* The parameters go in here for openssl. */

/* Debug flag.  Debugging does not reveal sensitive keys or data. */
static int DEBUG = 0;

struct rs_key
{
	char key[MAX_KEY_LEN]; /* secret shared key */
	unsigned keylen;       /* its length */
};

int
rs_init_crypt()
{
	int fd;
	char buf[128];
	int rv;

	if (DEBUG)
		rs_log("crypto: Initializing OpenSSL cryptography.");

	/* Seed the OpenSSL PRNG. */
	fd = open("/dev/urandom", O_RDONLY); /* FIXME */
	if (0 > fd)
		return -1;
	rv = read(fd, buf, sizeof(buf));
	close(fd);
	if (0 > rv)
		return -1;
	RAND_seed(buf, rv);

	/* Convert DH parameters from ascii to bignums. */
	DH_PARAM = DH_new();
	if (!DH_PARAM)
		return -1;
	DH_PARAM->p = DH_PARAM->g = NULL;
	if (!BN_hex2bn(&DH_PARAM->p, P))
		return -1;
	if (!BN_hex2bn(&DH_PARAM->g, G))
		return -1;
	if (DEBUG) {
		rs_log("crypto: DH key exchange P = %s", P);
		rs_log("crypto: DH key exchange G = %s", G);
	}
	return 0;
}

static rs_key_t
rs_key_new()
{
	rs_key_t key;
	key = (rs_key_t) malloc(sizeof(struct rs_key));
	if (!key)
		return NULL;
	bzero(key, sizeof(struct rs_key));
	return key;
}

int
rs_key_save(rs_key_t key, int fd)
{
	return rs_xwrite(fd, key, sizeof(*key));
}

rs_key_t
rs_key_restore(int fd)
{
	rs_key_t key;
	key = rs_key_new();
	if (!key)
		return NULL;
	if (0 > rs_xread(fd, key, sizeof(*key), 0))
		return NULL;
	return key;
}

void
rs_key_free(rs_key_t key)
{
	if (key) {
		bzero(key, sizeof(struct rs_key));
		free(key);
	}
}

rs_key_t
rs_key_exchange(int sock)
{
	unsigned long len, nlen;
	char buf[MAX_KEY_LEN];
	BIGNUM *peer_key;
	rs_key_t ret = NULL;
	rs_key_t key;

	if (DEBUG)
		rs_log("crypto: Begin DH key exchange");

	/* Make sure DH_generate_key and exit cleanup use fresh keys. */
	DH_PARAM->priv_key = NULL;

	key = rs_key_new();
	if (!key)
		goto out;

	/* Create the public and private DH keys from P and G */
	if (!DH_generate_key(DH_PARAM))
		goto out;

	/* Send our public key to peer. */
	len = BN_num_bytes(DH_PARAM->pub_key);
	assert(len <= MAX_KEY_LEN);
	BN_bn2bin(DH_PARAM->pub_key, buf);
	nlen = htonl(len);
	if (0 > rs_xwrite(sock, &nlen, sizeof(nlen)))
		goto out;
	if (0 > rs_xwrite(sock, buf, len))
		goto out;

	/* Receive peer's public key. */
	if (0 > rs_xread(sock, &nlen, sizeof(nlen), 0))
		goto out;
	len = ntohl(nlen);
	if (len > MAX_KEY_LEN)
		goto out;
	if (0 > rs_xread(sock, buf, len, 0))
		goto out;
	peer_key = BN_bin2bn(buf, len, NULL);
	if (!peer_key)
		goto out;

	/* Compute and store the secret shared key. */
	len = DH_compute_key(buf, peer_key, DH_PARAM);
	assert(len <= MAX_KEY_LEN);
	memcpy(key->key, buf, len);
	key->keylen = len;
	if (DEBUG)
		rs_log("crypto: established %d-bit key", len * 8);
	BN_free(peer_key);
	ret = key;
out:
	/* Free PRIV_KEY to get new keys next time. */
	BN_clear_free(DH_PARAM->priv_key);
	DH_PARAM->priv_key = NULL;
	if (!ret && DEBUG)
		rs_log("crypto: Key exchange error.");
	return ret;
}

static
char *ascii_text(unsigned char *bin, int len)
{
	/* This function is for debugging only. */
	static char buf[BUFLEN], *p;
	int i;

	for (i = 0, p = buf; i < len; i++, p += 2)
		sprintf(p, "%02x", bin[i]);
	buf[2*len] = '\0';
	return buf;
}

/* Return 1 if peer authenticated successfully
   Return 0 if peer failed
   Return -1 on error. */
int
rs_mutual_auth(rs_key_t key, int sock)
{
	char my_plain[BUFLEN];
	char my_cipher[BUFLEN];
	char peer_cipher[BUFLEN];
	char peer_plain[BUFLEN];
	char peer_reply[BUFLEN];
	unsigned char iv[EVP_MAX_IV_LENGTH]; /* Initial vector */
	EVP_CIPHER_CTX ex, dx;
	EVP_CIPHER *cp;
	int len, nlen, nl;
	int my_cipher_len, peer_cipher_len, peer_plain_len, peer_reply_len;
	int ret = -1;

	if (DEBUG)
		rs_log("crypto: Begin mutual authentication");

	/* Initialize */
	bzero(iv, EVP_MAX_IV_LENGTH); /* For Blowfish, okay to zero. */
	EVP_EncryptInit(&ex, CIPHER, key->key, iv);
	EVP_DecryptInit(&dx, CIPHER, key->key, iv);

	/* FIXME: This avoids warnings in older versions of openssl;
	   but this would be better:
	   EVP_CIPHER_CTX_key_length(&ex) = key->keylen;
	   EVP_CIPHER_CTX_key_length(&dx) = key->keylen;
	*/
	cp = (EVP_CIPHER *) EVP_CIPHER_CTX_cipher(&ex);
	EVP_CIPHER_key_length(cp) = key->keylen;
	cp = (EVP_CIPHER *) EVP_CIPHER_CTX_cipher(&dx);
	EVP_CIPHER_key_length(cp) = key->keylen;
	
	/* Encrypt unpredictable plaintext message. */
	if (!RAND_bytes(my_plain, MSGLEN))
		goto out;
	EVP_EncryptUpdate(&ex, my_cipher, &len, my_plain, MSGLEN);
	EVP_EncryptFinal(&ex, my_cipher + len, &nl);
	my_cipher_len = len + nl;
	if (my_cipher_len > BUFLEN)
		goto out;

	/* Send ciphertext challenge to peer. */
	nlen = htonl(my_cipher_len);
	if (0 > rs_xwrite(sock, &nlen, sizeof(nlen)))
		goto out;
	if (0 > rs_xwrite(sock, my_cipher, my_cipher_len))
		goto out;
	if (DEBUG)
		rs_log("crypto: Sent %d byte ciphertext challenge: %s",
		       MSGLEN, ascii_text(my_cipher, my_cipher_len));

	/* Receive ciphertext challenge from peer. */
	if (0 > rs_xread(sock, &nlen, sizeof(nlen), rs_opt_auth_timeout)) {
		rs_log("crypto: timeout or error reading crypto from peer");
		goto out;
	}
	peer_cipher_len = ntohl(nlen);
	if (peer_cipher_len > BUFLEN)
		goto out;
	if (0 > rs_xread(sock, peer_cipher, peer_cipher_len,
			 rs_opt_auth_timeout)) {
		rs_log("crypto: timeout or error reading crypto from peer");
		goto out;
	}
	if (DEBUG)
		rs_log("crypto: Received %d byte ciphertext challenge: %s",
		       peer_cipher_len,
		       ascii_text(peer_cipher, peer_cipher_len));

	/* Compute and send plaintext response. */
	EVP_DecryptUpdate(&dx, peer_plain, &len,
			  peer_cipher, peer_cipher_len);
	if (!EVP_DecryptFinal(&dx, peer_plain + len, &nl))
		goto out;
	peer_plain_len = len + nl;
	if (peer_plain_len > BUFLEN)
		goto out;
	nlen = htonl(peer_plain_len);
	if (0 > rs_xwrite(sock, &nlen, sizeof(nlen)))
		goto out;
	if (0 > rs_xwrite(sock, peer_plain, peer_plain_len))
		goto out;
	if (DEBUG)
		rs_log("crypto: Sent deciphered response to peer: %s",
		       ascii_text(peer_plain, peer_plain_len));

	/* Receive plaintext response. */
	if (0 > rs_xread(sock, &nlen, sizeof(nlen), rs_opt_auth_timeout)) {
		rs_log("crypto: timeout or error reading crypto from peer");		
		goto out;
	}
	peer_reply_len = ntohl(nlen);
	if (peer_reply_len > BUFLEN)
		goto out;
	if (0 > rs_xread(sock, peer_reply, peer_reply_len,
			 rs_opt_auth_timeout)) {
		rs_log("crypto: timeout or error reading crypto from peer");
		goto out;
	}
	if (DEBUG)
		rs_log("crypto: Received deciphered response from peer: %s",
		       ascii_text(peer_reply, peer_reply_len));

	/* Check */
	if (peer_reply_len == MSGLEN
	    && !memcmp(peer_reply, my_plain, MSGLEN)) {
		ret = 1;
		if (DEBUG)
			rs_log("crypto: Peer authenticated");
	} else {
		ret = 0;
		if (DEBUG)
			rs_log("crypto: Peer REJECTED");
	}
out:
	if (0 > ret && DEBUG)
		rs_log("crypto: Mutual authentication error.");
	return ret;
}
