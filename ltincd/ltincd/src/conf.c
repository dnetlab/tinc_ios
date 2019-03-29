/*
    conf.c -- configuration code
    Copyright (C) 1998 Robert van der Meulen
                  1998-2005 Ivo Timmermans
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
                  2010-2011 Julien Muchembled <jm@jmuchemb.eu>
                  2000      Cris van Pelt
                  2017-2018 Manav Kumar Mehta <manavkumarm@yahoo.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "avl_tree.h"
#include "connection.h"
#include "conf.h"
#include "list.h"
#include "logger.h"
#include "netutl.h"				/* for str2address */
#include "protocol.h"
#include "utils.h"				/* for cp */
#include "xalloc.h"

#define NUM_SERVER_CONNECTIONS 1
#define NUM_HOST_CONNECTIONS 2
#define MAX_SUBNET_LEN 40
#define MAX_ADDRESS_LEN 80

avl_tree_t *config_tree;

int pinginterval = 0;			/* seconds between pings */
int pingtimeout = 0;			/* seconds to wait for response */
char *confbase = NULL;			/* directory in which all config files are */
char *netname = NULL;			/* name of the vpn network */
list_t *cmdline_conf = NULL;	/* global/host configuration values given at the command line */

/********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
/* Hardcoded config settings for iOS */
/* If a setting is not required, assign the constant below to NULL */
char server_hostname[20] = "30"; // = "30"
const char *server_address_family = "ipv4";
const char *server_device = NULL;
const char *server_local_discovery = "yes";

char server_connections[NUM_SERVER_CONNECTIONS][20] = {
	"vpnserver"
};

char server_private_key[2048] =
"-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQCk2550Lha8Hh1nzp05rfwYAtgSPWBZlIcusk9/zIrz92btgP/k\n\
QnswA8VKzCZpwrfjjxYh+lYbRkVJjxcgyLTeNpkejJF6PFQhLODTK/MVcJjL2wbO\n\
kteoKDSckEBFZ2hGZBJQ1jCSHj4sC+ooTxRK2REAcI7cPPnD/GUJTgUJiwIDAQAB\n\
AoGAI2uweuPgLKEHzmL9MwRn0rzhseGQDw8zkFvtatcGz+5LJiJ+WIvULffRbwW4\n\
Byc4HWOD7N79mzSY9HoTDQ8ylOeyw21Xgvp78MbNYJjNZ2oGHjl4zsiZ+2qOcF6l\n\
wKn20VNXDUEfRH0+Nsi7yE0afwyNLu4Sp8S+hMvNPro+GAECQQDToJGKREOW31kD\n\
6rsW4cNIEPGA5WvhCMg2qcHPC3ft5Mk6mxStZMwIVtLpzOzxBZENN+Mys5UKS+jM\n\
jnQ8xhwBAkEAx2yhlmIUMb0Uwl2kofd7guDS7HcC24ljc6BvptL3setGugMkOwot\n\
KO0JxrXbVwZ8uh4sXPiR4FWUdXNhNSfViwJBAJHrxI7nNQeh55oIz4oej21wqWVs\n\
S+92A7+VW9qsmLxDJfGwHxjUSM9zNqkZsUMbyIGpyJIcO6dG4jWyADorjAECQFvO\n\
HI04VYeYPehEZ7fQUGGt0ivdlcku9EOUhhHMaQ7U+thC/fjX9HY0uR1rNrBXYi/k\n\
GBQssisN+qwfE47+6YUCQAZHI8V2Ki/M6RwxhXCXqiGxpM/Fn3jw84DyncYPVCfD\n\
S86ltAIrOP1pPSW3CAoNdpVG4uQHkIc7P1DrpTxfjhs=\n\
-----END RSA PRIVATE KEY-----\n";

char host_config_hostnames[NUM_HOST_CONNECTIONS][20] = {
	"vpnserver",
    "30"
};

char host_config_addresses[NUM_HOST_CONNECTIONS][MAX_ADDRESS_LEN] = {
	"67.218.153.97 50073",
    ""
};

char host_config_subnets[NUM_HOST_CONNECTIONS][MAX_SUBNET_LEN] = {
	"10.0.1.1/32",
    "10.0.1.30/32"
};

char host_config_pubkeys[NUM_HOST_CONNECTIONS][2048] = {
/* host1 */
"-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBAKTbnnQuFrweHWfOnTmt/BgC2BI9YFmUhy6yT3/MivP3Zu2A/+RCezAD\n\
xUrMJmnCt+OPFiH6VhtGRUmPFyDItN42mR6MkXo8VCEs4NMr8xVwmMvbBs6S16go\n\
NJyQQEVnaEZkElDWMJIePiwL6ihPFErZEQBwjtw8+cP8ZQlOBQmLAgMBAAE=\n\
-----END RSA PUBLIC KEY-----\n",

/* host2 */
"-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBAKTbnnQuFrweHWfOnTmt/BgC2BI9YFmUhy6yT3/MivP3Zu2A/+RCezAD\n\
xUrMJmnCt+OPFiH6VhtGRUmPFyDItN42mR6MkXo8VCEs4NMr8xVwmMvbBs6S16go\n\
NJyQQEVnaEZkElDWMJIePiwL6ihPFErZEQBwjtw8+cP8ZQlOBQmLAgMBAAE=\n\
-----END RSA PUBLIC KEY-----\n"
};

void set_local_conf(char* name, char* subnet, char* host_address, char* pub_key, char* pri_key)
{
    logger(LOG_ERR, "----- set local conf -----");
    if (name)
    {
        logger(LOG_ERR, "name:%s\n", name);
        strncpy(server_hostname, name, sizeof(server_hostname) - 1);
        strncpy(host_config_hostnames[1], name, sizeof(host_config_hostnames[1]) - 1);
    }
    if (subnet)
    {
        logger(LOG_ERR, "subnet:%s\n", subnet);
        strncpy(host_config_subnets[1], subnet, sizeof(host_config_subnets[1]) - 1);
    }
    if (host_address)
    {
        logger(LOG_ERR, "host_address:%s\n", host_address);
        strncpy(host_config_addresses[1], host_address, sizeof(host_config_addresses[1]) - 1);
    }
    if (pub_key)
    {
        logger(LOG_ERR, "before pub_key:%s\n", pub_key);
        strncpy(host_config_pubkeys[1], pub_key, sizeof(host_config_pubkeys[1]) - 1);
        logger(LOG_ERR, "after pub_key:%s\n", host_config_pubkeys[1]);
    }
    if (pri_key)
    {
        logger(LOG_ERR, "before pri_key:%s\n", pri_key);
        strncpy(server_private_key, pri_key, sizeof(server_private_key) - 1);
        logger(LOG_ERR, "after pri_key:%s\n", server_private_key);
    }
    return;
}

void set_server_conf(char* name, char* subnet, char* host_address, char* pub_key)
{
    logger(LOG_ERR, "----- set server conf -----");
    if (name)
    {
        logger(LOG_ERR, "name:%s\n", name);
        strncpy(server_connections[0], name, sizeof(server_connections[0]) - 1);
        strncpy(host_config_hostnames[0], name, sizeof(host_config_hostnames[0]) - 1);
    }
    if (subnet)
    {
        logger(LOG_ERR, "subnet:%s\n", subnet);
        strncpy(host_config_subnets[0], subnet, sizeof(host_config_subnets[0]) - 1);
    }
    if (host_address)
    {
        logger(LOG_ERR, "host_address:%s\n", host_address);
        strncpy(host_config_addresses[0], host_address, sizeof(host_config_addresses[0]) - 1);
    }
    if (pub_key)
    {
        logger(LOG_ERR, "before pub_key:%s\n", pub_key);
        strncpy(host_config_pubkeys[0], pub_key, sizeof(host_config_pubkeys[0]) - 1);
        logger(LOG_ERR, "after pub_key:%s\n", host_config_pubkeys[0]);
    }
    return;
}

/* added by dailei */
ipv4_t supernode_ip;
int set_supernode(char* supernode)
{
    int ret = -1;
    if (supernode)
    {
        uint32_t tmp1;
        uint32_t tmp2;
        uint32_t tmp3;
        uint32_t tmp4;
        int scan_ret = sscanf(supernode, "%u.%u.%u.%u", &tmp1, &tmp2, &tmp3, &tmp4);
        if (scan_ret == 4)
        {
            ret = 0;
            supernode_ip.x[0] = (uint8_t)(tmp1 & 0xff);
            supernode_ip.x[1] = (uint8_t)(tmp2 & 0xff);
            supernode_ip.x[2] = (uint8_t)(tmp3 & 0xff);
            supernode_ip.x[3] = (uint8_t)(tmp4 & 0xff);
        }
    }
    return ret;
}

void add_hardcoded_config(avl_tree_t *config_tree, const char *var, const char *val, const char *fname,
													int lineno) {
  config_t *cfg = new_config();

	cfg->variable = xstrdup(var);
	cfg->value = xstrdup(val);
	cfg->file = fname ? xstrdup(fname) : NULL;
  cfg->line = lineno;

  config_add(config_tree, cfg);

  return;
}

bool add_hardcoded_connection_config(avl_tree_t *config_tree, const char *hostname, const char *fname) {
	int i;
	int line = 0;

	for (i = 0; i < NUM_HOST_CONNECTIONS; i++) {
		if (0 == strcmp(host_config_hostnames[i], hostname)) {
			if (host_config_addresses[i] && host_config_addresses[i][0]) {
				add_hardcoded_config(config_tree, "Address", host_config_addresses[i], fname, ++line);
			}
			if (host_config_subnets[i] && host_config_subnets[i][0]) {
				add_hardcoded_config(config_tree, "Subnet", host_config_subnets[i], fname, ++line);
			}
			return true;
		}
	}

	return false;
}

const char *get_hardcoded_public_key(const char *hostname) {
	int i;

	for (i = 0; i < NUM_HOST_CONNECTIONS; i++) {
		if (0 == strcmp(host_config_hostnames[i], hostname)) {
			return host_config_pubkeys[i];
		}
	}

	return NULL;
}

/********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/



static int config_compare(const config_t *a, const config_t *b) {
	int result;

	result = strcasecmp(a->variable, b->variable);

	if(result)
		return result;

	/* give priority to command line options */
	result = !b->file - !a->file;
	if (result)
		return result;

	result = a->line - b->line;

	if(result)
		return result;
	else
		return a->file ? strcmp(a->file, b->file) : 0;
}

void init_configuration(avl_tree_t ** config_tree) {
	*config_tree = avl_alloc_tree((avl_compare_t) config_compare, (avl_action_t) free_config);
}

void exit_configuration(avl_tree_t ** config_tree) {
	avl_delete_tree(*config_tree);
	*config_tree = NULL;
}

config_t *new_config(void) {
	return xmalloc_and_zero(sizeof(config_t));
}

void free_config(config_t *cfg) {
	if(cfg->variable)
		free(cfg->variable);

	if(cfg->value)
		free(cfg->value);

	if(cfg->file)
		free(cfg->file);

	free(cfg);
}

void config_add(avl_tree_t *config_tree, config_t *cfg) {
	avl_insert(config_tree, cfg);
}

config_t *lookup_config(const avl_tree_t *config_tree, char *variable) {
	config_t cfg, *found;

	cfg.variable = variable;
	cfg.file = NULL;
	cfg.line = 0;

	found = avl_search_closest_greater(config_tree, &cfg);

	if(!found)
		return NULL;

	if(strcasecmp(found->variable, variable))
		return NULL;

	return found;
}

config_t *lookup_config_next(const avl_tree_t *config_tree, const config_t *cfg) {
	avl_node_t *node;
	config_t *found;

	node = avl_search_node(config_tree, cfg);

	if(node) {
		if(node->next) {
			found = node->next->data;

			if(!strcasecmp(found->variable, cfg->variable))
				return found;
		}
	}

	return NULL;
}

bool get_config_bool(const config_t *cfg, bool *result) {
	if(!cfg)
		return false;

	if(!strcasecmp(cfg->value, "yes")) {
		*result = true;
		return true;
	} else if(!strcasecmp(cfg->value, "no")) {
		*result = false;
		return true;
	}

	logger(LOG_ERR, "\"yes\" or \"no\" expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_int(const config_t *cfg, int *result) {
	if(!cfg)
		return false;

	if(sscanf(cfg->value, "%d", result) == 1)
		return true;

	logger(LOG_ERR, "Integer expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_string(const config_t *cfg, char **result) {
	if(!cfg)
		return false;

	*result = xstrdup(cfg->value);

	return true;
}

bool get_config_address(const config_t *cfg, struct addrinfo **result) {
	struct addrinfo *ai;

	if(!cfg)
		return false;

	ai = str2addrinfo(cfg->value, NULL, 0);

	if(ai) {
		*result = ai;
		return true;
	}

	logger(LOG_ERR, "Hostname or IP address expected for configuration variable %s in %s line %d",
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool get_config_subnet(const config_t *cfg, subnet_t ** result) {
	subnet_t subnet = {NULL};

	if(!cfg)
		return false;

	if(!str2net(&subnet, cfg->value)) {
		logger(LOG_ERR, "Subnet expected for configuration variable %s in %s line %d",
			   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	/* Teach newbies what subnets are... */

	if(((subnet.type == SUBNET_IPV4)
		&& !maskcheck(&subnet.net.ipv4.address, subnet.net.ipv4.prefixlength, sizeof(ipv4_t)))
		|| ((subnet.type == SUBNET_IPV6)
		&& !maskcheck(&subnet.net.ipv6.address, subnet.net.ipv6.prefixlength, sizeof(ipv6_t)))) {
		logger(LOG_ERR, "Network address and prefix length do not match for configuration variable %s in %s line %d",
			   cfg->variable, cfg->file, cfg->line);
		return false;
	}

	*(*result = new_subnet()) = subnet;

	return true;
}

/*
  Read exactly one line and strip the trailing newline if any.
*/
static char *readline(FILE * fp, char *buf, size_t buflen) {
	char *newline = NULL;
	char *p;

	if(feof(fp))
		return NULL;

	p = fgets(buf, buflen, fp);

	if(!p)
		return NULL;

	newline = strchr(p, '\n');

	if(!newline)
		return buf;

	*newline = '\0';	/* kill newline */
	if(newline > p && newline[-1] == '\r')	/* and carriage return if necessary */
		newline[-1] = '\0';

	return buf;
}

config_t *parse_config_line(char *line, const char *fname, int lineno) {
	config_t *cfg;
	int len;
	char *variable, *value, *eol;
	variable = value = line;

	eol = line + strlen(line);
	while(strchr("\t ", *--eol))
		*eol = '\0';

	len = strcspn(value, "\t =");
	value += len;
	value += strspn(value, "\t ");
	if(*value == '=') {
		value++;
		value += strspn(value, "\t ");
	}
	variable[len] = '\0';

	if(!*value) {
		const char err[] = "No value for variable";
		if (fname)
			logger(LOG_ERR, "%s `%s' on line %d while reading config file %s",
				err, variable, lineno, fname);
		else
			logger(LOG_ERR, "%s `%s' in command line option %d",
				err, variable, lineno);
		return NULL;
	}

	cfg = new_config();
	cfg->variable = xstrdup(variable);
	cfg->value = xstrdup(value);
	cfg->file = fname ? xstrdup(fname) : NULL;
	cfg->line = lineno;

	return cfg;
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
bool read_config_file(avl_tree_t *config_tree, const char *fname) {
	FILE *fp;
	char buffer[MAX_STRING_SIZE];
	char *line;
	int lineno = 0;
	bool ignore = false;
	config_t *cfg;
	bool result = false;

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, "Cannot open config file %s: %s", fname, strerror(errno));
		return false;
	}

	for(;;) {
		line = readline(fp, buffer, sizeof buffer);

		if(!line) {
			if(feof(fp))
				result = true;
			break;
		}

		lineno++;

		if(!*line || *line == '#')
			continue;

		if(ignore) {
			if(!strncmp(line, "-----END", 8))
				ignore = false;
			continue;
		}
		
		if(!strncmp(line, "-----BEGIN", 10)) {
			ignore = true;
			continue;
		}

		cfg = parse_config_line(line, fname, lineno);
		if (!cfg)
			break;
		config_add(config_tree, cfg);
	}

	fclose(fp);

	return result;
}

void read_config_options(avl_tree_t *config_tree, const char *prefix) {
	list_node_t *node, *next;
	size_t prefix_len = prefix ? strlen(prefix) : 0;

	for(node = cmdline_conf->tail; node; node = next) {
		config_t *orig_cfg, *cfg = (config_t *)node->data;
		next = node->prev;

		if(!prefix) {
			if(strchr(cfg->variable, '.'))
				continue;
			node->data = NULL;
			list_unlink_node(cmdline_conf, node);
		} else {
			if(strncmp(prefix, cfg->variable, prefix_len) ||
			   cfg->variable[prefix_len] != '.')
				continue;
			/* Because host configuration is parsed again when
			   reconnecting, nodes must not be freed when a prefix
			   is given. */
			orig_cfg = cfg;
			cfg = new_config();
			cfg->variable = xstrdup(orig_cfg->variable + prefix_len + 1);
			cfg->value = xstrdup(orig_cfg->value);
			cfg->file = NULL;
			cfg->line = orig_cfg->line;
		}
		config_add(config_tree, cfg);
	}
}

bool read_server_config(void) {
	char *fname;
	bool x;
    /********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
	/* Set up hardcoded configuration */
	int i;
	int line = 0;

	x = true;
	if (server_hostname && server_hostname[0]) {
		add_hardcoded_config(config_tree, "Name", server_hostname, "tinc.conf", ++line);
	}
	if (server_address_family) {
		add_hardcoded_config(config_tree, "AddressFamily", server_address_family, "tinc.conf", ++line);
	}
	if (server_device) {
		add_hardcoded_config(config_tree, "Device", server_device, "tinc.conf", ++line);
	}
	for (i = 0; i < NUM_SERVER_CONNECTIONS; i++) {
		if (server_connections[i] && server_connections[i][0]) {
			add_hardcoded_config(config_tree, "ConnectTo", server_connections[i], "tinc.conf", ++line);
		}
	}
	if (server_local_discovery) {
		add_hardcoded_config(config_tree, "LocalDiscovery", server_local_discovery, "tinc.conf", ++line);
	}
    /********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

	read_config_options(config_tree, NULL);

    /********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
    // Comment out existing code for reading config from files
/*
	xasprintf(&fname, "%s/tinc.conf", confbase);
	x = read_config_file(config_tree, fname);

	// We will try to read the conf files in the "conf.d" dir
	if (x) {
		char * dname;
		xasprintf(&dname, "%s/conf.d", confbase);
		DIR *dir = opendir (dname);
		// If we can find this dir
		if (dir) { 
			struct dirent *ep;
			// We list all the files in it
			while (x && (ep = readdir (dir))) {
				size_t l = strlen(ep->d_name);
				// And we try to read the ones that end with ".conf"
				if (l > 5 && !strcmp(".conf", & ep->d_name[ l - 5 ])) {
					free(fname);
					xasprintf(&fname, "%s/%s", dname, ep->d_name);
					x = read_config_file(config_tree, fname);
				}
			}
			closedir (dir);
		}
		free(dname);
	}

	if(!x) {		*/		/* System error: complain */
/*		logger(LOG_ERR, "Failed to read `%s': %s", fname, strerror(errno));
	}

	free(fname); */
    /********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

	return x;
}

bool read_connection_config(connection_t *c) {
	char *fname;
	bool x;

    /********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
	/* Set up hardcoded configuration */
/*
	read_config_options(c->config_tree, c->name);
*/
	xasprintf(&fname, "%s/hosts/%s", confbase, c->name);
/*	x = read_config_file(c->config_tree, fname); */

	x = true;
	if (!add_hardcoded_connection_config(c->config_tree, c->name, fname)) {
		logger(LOG_ERR, "Could not locate hardcoded connection config for %s", c->name);
		x = false;
	}
    /********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

	free(fname);

	return x;
}

static void disable_old_keys(const char *filename) {
	char tmpfile[PATH_MAX] = "";
	char buf[1024];
	bool disabled = false;
	FILE *r, *w;

	r = fopen(filename, "r");
	if(!r)
		return;

	snprintf(tmpfile, sizeof tmpfile, "%s.tmp", filename);

	w = fopen(tmpfile, "w");

	while(fgets(buf, sizeof buf, r)) {
		if(!strncmp(buf, "-----BEGIN RSA", 14)) {	
			buf[11] = 'O';
			buf[12] = 'L';
			buf[13] = 'D';
			disabled = true;
		}
		else if(!strncmp(buf, "-----END RSA", 12)) {	
			buf[ 9] = 'O';
			buf[10] = 'L';
			buf[11] = 'D';
			disabled = true;
		}
		if(w && fputs(buf, w) < 0) {
			disabled = false;
			break;
		}
	}

	if(w)
		fclose(w);
	fclose(r);

	if(!w && disabled) {
		fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");
		return;
	}

	if(disabled) {
#ifdef HAVE_MINGW
		// We cannot atomically replace files on Windows.
		char bakfile[PATH_MAX] = "";
		snprintf(bakfile, sizeof bakfile, "%s.bak", filename);
		if(rename(filename, bakfile) || rename(tmpfile, filename)) {
			rename(bakfile, filename);
#else
		if(rename(tmpfile, filename)) {
#endif
			fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");
		} else  {
#ifdef HAVE_MINGW
			unlink(bakfile);
#endif
			fprintf(stderr, "Warning: old key(s) found and disabled.\n");
		}
	}

	unlink(tmpfile);
}

FILE *ask_and_open(const char *filename, const char *what) {
	FILE *r;
	char *directory;
	char line[PATH_MAX];
	const char *fn;

	/* Check stdin and stdout */
	if(!isatty(0) || !isatty(1)) {
		/* Argh, they are running us from a script or something.  Write
		   the files to the current directory and let them burn in hell
		   for ever. */
		fn = filename;
	} else {
		/* Ask for a file and/or directory name. */
		fprintf(stdout, "Please enter a file to save %s to [%s]: ",
				what, filename);
		fflush(stdout);

		fn = readline(stdin, line, sizeof line);

		if(!fn) {
			fprintf(stderr, "Error while reading stdin: %s\n",
					strerror(errno));
			return NULL;
		}

		if(!strlen(fn))
			/* User just pressed enter. */
			fn = filename;
	}

#ifdef HAVE_MINGW
	if(fn[0] != '\\' && fn[0] != '/' && !strchr(fn, ':')) {
#else
	if(fn[0] != '/') {
#endif
		/* The directory is a relative path or a filename. */
		char *p;

		directory = get_current_dir_name();
		xasprintf(&p, "%s/%s", directory, fn);
		free(directory);
		fn = p;
	}

	umask(0077);				/* Disallow everything for group and other */

	disable_old_keys(fn);

	/* Open it first to keep the inode busy */

	r = fopen(fn, "a");

	if(!r) {
		fprintf(stderr, "Error opening file `%s': %s\n",
				fn, strerror(errno));
		return NULL;
	}

	return r;
}


