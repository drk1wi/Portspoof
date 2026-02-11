/*
 *   Portspoof  - Service Signature Emulator  / Exploitation Framework Frontend   
 *   Copyright (C) 2012 Piotr Duszyński <piotr[at]duszynski.eu>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 * 
 *   Linking portspoof statically or dynamically with other modules is making
 *   a combined work based on Portspoof. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 * 
 *   In addition, as a special exception, the copyright holder of Portspoof
 *   gives you permission to combine Portspoof with free software programs or
 *   libraries that are released under the GNU LGPL. You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   Portspoof and the licenses of the other code concerned.
 * 
 *   Note that people who make modified versions of Portspoof are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */


#ifndef UTILS_H
#define UTILS_H


#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <syslog.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>

#include "Configuration.h"

class Configuration;
extern Configuration* configuration;

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

#define MAX_LOG_MSG_LEN 200
#define SYSLOG_NAME "portspoof"
#define FUZZING_KEYWORD "__FUZZ__"

using namespace std;

class Utils
{
public:
    static void hexdump(void* mem, unsigned int len);
    static int isNumeric(const char* s);
    static std::string get_substring_value(char* str);
    static std::vector<char> wrapNMAP(string wrapper, std::vector<char> payload);
    static std::vector<char> unescape(std::vector<char>& s);
    static std::vector<char> str2vector(std::string& s);
    static void log_create(const char* file);
    static void log_write(Configuration* configuration, const char* msg);
    static void daemonize(Configuration* configuration);
};


#endif