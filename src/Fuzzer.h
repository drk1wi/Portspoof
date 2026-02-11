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


#ifndef FUZZER_H
#define FUZZER_H

#include <string>
#include <stdio.h>
#include <ctype.h>
#include <map>
#include <vector>
#include <sstream>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <ctime>
#include <pthread.h>
#include <iostream>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

#include "Utils.h"
#include "Configuration.h"

using namespace std;

#define NMAP_FUZZ_FILE_SIG "nmapfuzzsignatures"
#define FUZZ_FILE_PAYLOAD "nmapfuzzpayloads"

static const char* const fuzz_oracle[] =
{
    "A",
    "%n%n%n%n%n",
    "%%20n",
    "%n%p%s%d%x",
    "%.1024d",
    "%.2049d",
    "-1",
    "32767",
    "65535",
    "-2147483647",
    "0xffffffff",
    "a|id > /tmp/FZ|b",
    "a`id > /tmp/FZ`b",
    "a'id > /tmp/FZ'b",
    "a;id > /tmp/FZ;b",
    "a&&id > /tmp/FZ&&b"
};


class Fuzzer
{
private:
    std::string nmapfuzzsignatures_file;
    std::string fuzzpayload_file;
    Nmap_Fuzz_Vector nmapfuzzsignatures;
    FILE* fp_payloads;
    std::vector<char> input_line;
    Configuration* configuration;
    int counter;
    int payload_counter;
    int nmapfuzzsignatures_size;

public:
    Fuzzer();
    Fuzzer(Configuration* configuration);
    bool processSignatureFile();
    std::vector<char> GetFUZZ();
    std::vector<char> GenerateFuzzPayload();
    std::vector<char> intToBytes(int paramInt);
    std::vector<char> shortToBytes(unsigned short paramInt);

    bool PrepareFuzzer();
};


#endif