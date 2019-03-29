/*
 logger.c -- logging code
 Copyright (C) 2004-2016 Guus Sliepen <guus@tinc-vpn.org>
               2004-2005 Ivo Timmermans
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

#ifndef __TINC_LOGGER_H__
#define __TINC_LOGGER_H__

typedef enum debug_t {
	DEBUG_NOTHING = 0,			/* Quiet mode, only show starting/stopping of the daemon */
	DEBUG_ALWAYS = 0,
	DEBUG_CONNECTIONS = 1,		/* Show (dis)connects of other tinc daemons via TCP */
	DEBUG_ERROR = 2,			/* Show error messages received from other hosts */
	DEBUG_STATUS = 2,			/* Show status messages received from other hosts */
	DEBUG_PROTOCOL = 3,			/* Show the requests that are sent/received */
	DEBUG_META = 4,				/* Show contents of every request that is sent/received */
	DEBUG_TRAFFIC = 5,			/* Show network traffic information */
	DEBUG_PACKET = 6,			/* Show contents of each packet that is being sent/received */
	DEBUG_SCARY_THINGS = 10		/* You have been warned */
} debug_t;

typedef enum logmode_t {
	LOGMODE_NULL,
	LOGMODE_STDERR,
	LOGMODE_FILE,
	LOGMODE_SYSLOG
} logmode_t;

#ifdef HAVE_MINGW
#define LOG_EMERG EVENTLOG_ERROR_TYPE
#define LOG_ALERT EVENTLOG_ERROR_TYPE
#define LOG_CRIT EVENTLOG_ERROR_TYPE
#define LOG_ERR EVENTLOG_ERROR_TYPE
#define LOG_WARNING EVENTLOG_WARNING_TYPE
#define LOG_NOTICE EVENTLOG_INFORMATION_TYPE
#define LOG_INFO EVENTLOG_INFORMATION_TYPE
#define LOG_DEBUG EVENTLOG_INFORMATION_TYPE
#else
#ifndef HAVE_SYSLOG_H
enum {
	LOG_EMERG,
	LOG_ALERT,
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
};
#endif
#endif

/********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
// Declarations for printing log messages to iOS App
#define LOG_BUFFER_SIZE 255
void setlogcb(void (*cb)(const char *, void *), void *ctxt);
/********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

extern debug_t debug_level;
extern void openlogger(const char *, logmode_t);
extern void reopenlogger(void);
extern void logger(int, const char *, ...) __attribute__ ((__format__(printf, 2, 3)));
extern void closelogger(void);

#define ifdebug(l) if(debug_level >= DEBUG_##l)

#endif /* __TINC_LOGGER_H__ */
