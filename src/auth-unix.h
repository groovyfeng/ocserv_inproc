/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef OC_AUTH_UNIX_H
#define OC_AUTH_UNIX_H

# include "config.h"

#if defined(HAVE_GSSAPI) || defined(HAVE_PAM)
# define HAVE_GET_USER_AUTH_GROUP
#endif

#ifdef HAVE_GET_USER_AUTH_GROUP
int get_user_auth_group(const char *username, const char *suggested,
			char *groupname, int groupname_size);
void unix_group_list(void *pool, unsigned gid_min, char ***groupname, unsigned *groupname_size);
#endif

#endif
