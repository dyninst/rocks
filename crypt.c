/* 
 *  rocks/crypt.c
 *
 *  Common cryptography interface.
 *
 *  Copyright (C) 2001 Victor Zandy
 *  See COPYING for distribution terms.
 */

#include "rs.h"

int
rs_authenticate(rs_key_t key, int sock)
{
	return rs_mutual_auth(key, sock);
}
