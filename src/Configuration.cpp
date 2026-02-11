/*
 *   Portspoof  - Service Signature Emulator  / Exploitation Framework Frontend
 *   Copyright (C) 2012 Piotr Duszynski <piotr[at]duszynski.eu>
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


#include "Configuration.h"

Configuration::Configuration()
{
    configfile = std::string(CONF_FILE);
    signaturefile = std::string(SIGNATURE_FILE);
    logfile = std::string(LOG_FILE);
    bind_ip = std::string();
    username = std::string(DAEMON_USER);
    group = std::string(DAEMON_USER);

    port = DEFAULT_PORT;
    opts = 0;
    nmapfuzzsignatures_file = std::string(NMAP_FUZZ_FILE_SIG);
    fuzzpayload_file = std::string(FUZZ_FILE_PAYLOAD);
    thread_number = 10;
    fuzzing_mode = 0;
    tarpit_min = DEFAULT_TARPIT_MIN;
    tarpit_max = DEFAULT_TARPIT_MAX;
    memset(port_timeouts, 0, sizeof(port_timeouts));
    memset(port_behaviors, 0, sizeof(port_behaviors));
    return;
}

bool Configuration::getConfigValue(int value)
{
    return this->opts[value];
}

void Configuration::usage(void)
{
    fprintf(stdout, "Usage: portspoof [OPTION]...\n"
            "Portspoof - service emulator / frontend exploitation framework.\n\n"
            "-i			  ip : Bind to a particular  IP address\n"
            "-p			  port : Bind to a particular PORT number\n"
            "-s			  file_path : Portspoof service signature regex. file\n"
            "-c			  file_path : Portspoof configuration file\n"
            "-l			  file_path : Log port scanning alerts to a file\n"
            "-f			  file_path : FUZZER_MODE - fuzzing payload file list \n"
            "-n			  file_path : FUZZER_MODE - wrapping signatures file list\n"
            "-1			  FUZZER_MODE - generate fuzzing payloads internally\n"
            "-2			  switch to simple reply mode (doesn't work for Nmap)!\n"
            "-t			  seconds : Minimum hold time (default: 0)\n"
            "-T			  seconds : Maximum hold time (default: 120)\n"
            "-D			  run as daemon process\n"
            "-d			  disable syslog\n"
            "-v			  be verbose\n"
            "-h			  display this help and exit\n");

    exit(1);
}

bool Configuration::processArgs(int argc, char** argv)
{
    int ch;
    extern char* __progname;

    while ((ch = getopt(argc, argv, "l:i:p:s:c:f:n:t:T:dvh12D")) != -1)
    {
        switch (ch)
        {
        case 'i':
            this->bind_ip = std::string(optarg);
            this->opts[OPT_IP] = 1;
            break;
        case 'p':
            this->port = atoi(optarg);
            this->opts[OPT_PORT] = 1;
            break;
        case 's':
            this->signaturefile = std::string(optarg);
            fprintf(stdout, "-> Using user defined signature file %s\n", this->signaturefile.c_str());
            this->opts[OPT_SIG_FILE] = 1;

            break;
        case 'c':
            this->configfile = std::string(optarg);
            this->opts[OPT_CONFIG_FILE] = 1;
            fprintf(stdout, "-> Using user defined configuration file %s\n", this->configfile.c_str());
            break;
        case 'v':
            this->opts[OPT_DEBUG] = 1;
            fprintf(stdout, "-> Verbose mode on.\n");
            break;
        case 'd':
            this->opts[OPT_SYSLOG_DIS] = 1;
            fprintf(stdout, "-> Syslog logging disabled.\n");
            break;
        case 'D':
            this->opts[OPT_RUN_AS_D] = 1;
            break;
        case 'l':
            this->opts[OPT_LOG_FILE] = 1;
            this->logfile = std::string(optarg);
            fprintf(stdout, "-> Using log file %s\n", this->logfile.c_str());
            //check log file
            Utils::log_create(configuration->getLogFile().c_str());
            break;
        case 'f':
            this->opts[OPT_FUZZ_WORDLIST] = 1;
            this->fuzzpayload_file = std::string(optarg);
            if (this->opts[OPT_FUZZ_INTERNAL])
            {
                fprintf(stdout, "Error: -1 flag cannot be used with -f \n\n");
                exit(0);
            }
            fprintf(stdout, "-> Reading fuzzing payloads from a file %s!\n", this->fuzzpayload_file.c_str());
            break;
        case 'n':
            this->opts[OPT_FUZZ_NMAP] = 1;
            this->nmapfuzzsignatures_file = std::string(optarg);
            fprintf(stdout, "-> Payload wrapping mode!\n");
            break;
        case '1':
            this->opts[OPT_FUZZ_INTERNAL] = 1;
            if (this->opts[OPT_FUZZ_WORDLIST])
            {
                fprintf(stdout, "Error: -f flag cannot be used with -1 \n\n");
                exit(0);
            }
            fprintf(stdout, "-> Generating fuzzing payloads internally!\n");

            break;
        case '2':
            this->opts[OPT_NOT_NMAP_SCANNER] = 1;
            fprintf(stdout, "-> Switching to simple reply mode (anything apart from Nmap)!\n");
            break;
        case 't':
            this->tarpit_min = atoi(optarg) * 1000;
            this->opts[OPT_TARPIT_MIN] = 1;
            fprintf(stdout, "-> Tarpit minimum hold: %dms\n", this->tarpit_min);
            break;
        case 'T':
            this->tarpit_max = atoi(optarg) * 1000;
            this->opts[OPT_TARPIT_MAX] = 1;
            fprintf(stdout, "-> Tarpit maximum hold: %dms\n", this->tarpit_max);
            break;
        case 'h':
            this->usage();
            break;
        default:
            fprintf(stdout, "Try ` %s -h' for more information.\n\n", __progname);
            exit(0);
            break;
        }
    }


    if (this->opts == 0)
    {
        fprintf(stdout, "-> No parameters - switching to simple 'open port' mode.\n");
    }

    if (this->getConfigValue(OPT_FUZZ_NMAP) || this->getConfigValue(OPT_FUZZ_WORDLIST) || this->getConfigValue(
        OPT_FUZZ_INTERNAL))
    {
        this->fuzzer = new Fuzzer(this);
        this->thread_number = 1; //set thread count to 1 due to race conditions
        this->fuzzing_mode = 1;
    }

    if (this->fuzzing_mode == 0)
    {
        if (this->opts[OPT_SIG_FILE] && this->processSignatureFile())
            exit(1);

        if (this->opts[OPT_CONFIG_FILE] && this->readConfigFile())
            exit(1);

        if (this->generateBufferSize())
            exit(1);
    }

    /* generate per-port hold times and behavioral modes */
    generateTimeouts();
    generateBehaviors();

    return 0;
}

std::string Configuration::getConfigFile()
{
    return this->configfile;
}

std::string Configuration::getSignatureFile()
{
    return this->signaturefile;
}

std::string Configuration::getNmapfuzzSignaturesFile()
{
    return this->nmapfuzzsignatures_file;
}

std::string Configuration::getFuzzPayloadFile()
{
    return this->fuzzpayload_file;
}

std::string Configuration::getLogFile()
{
    return this->logfile;
}

std::string Configuration::getBindIP()
{
    return this->bind_ip;
}

unsigned short int Configuration::getPort()
{
    return this->port;
}


int Configuration::getThreadNr()
{
    return this->thread_number;
}


int Configuration::getUserid()
{
    struct passwd* pwd = getpwnam(this->username.c_str());
    if (pwd) return pwd->pw_uid;

    return -1;
}


int Configuration::getGroupid()
{
    struct group* grp = getgrnam(this->group.c_str());
    if (grp) return grp->gr_gid;

    return -1;
}


std::vector<char> Configuration::mapPort2Signature(unsigned short port)
{
    if (this->opts[OPT_FUZZ_NMAP] || this->opts[OPT_FUZZ_INTERNAL] || this->opts[OPT_FUZZ_WORDLIST])
    {
        std::vector<char> result_vector;
        result_vector = this->fuzzer->GetFUZZ();
        return result_vector;
    }
    else
        return this->portsignatureemap[port];
}


const std::vector<char>* Configuration::getSignaturePtr(unsigned short port)
{
    Port_Signature_Map::iterator it = portsignatureemap.find(port);
    if (it != portsignatureemap.end())
        return &(it->second);
    return NULL;
}


bool Configuration::isFuzzing()
{
    return this->fuzzing_mode;
}


unsigned int Configuration::mapPort2Buffer(unsigned short port)
{
    if (this->opts[OPT_FUZZ_NMAP] || this->opts[OPT_FUZZ_INTERNAL] || this->opts[OPT_FUZZ_WORDLIST])
        return MAX_BUFFER_SIZE;
    else
        return this->portbuffermap[port];
}


bool Configuration::processSignatureFile()
{
    char buf_file[BUFSIZE];

    FILE* fp = fopen(this->signaturefile.c_str(), "r");
    if (fp == NULL)
    {
        fprintf(stdout, "Error opening signature file: %s \n", this->signaturefile.c_str());
        return 1;
    }

    while (fgets(buf_file, BUFSIZE, fp))
        rawsignatures.push_back(std::string(buf_file));

    fclose(fp);

    /* seed from urandom if possible */
    uint32_t seed = 0;
    FILE* rng = fopen("/dev/urandom", "rb");
    if (rng)
    {
        if (fread(&seed, sizeof(seed), 1, rng) < 1)
            seed = (uint32_t)time(0) ^ (uint32_t)getpid();
        fclose(rng);
    }
    else
    {
        seed = (uint32_t)time(0) ^ (uint32_t)getpid();
    }
    srand(seed);

    for (int i = 0; i <= MAX_PORTS; i++)
    {
        portsignatureemap.insert(make_pair(i, process_signature(rawsignatures[rand() % rawsignatures.size()])));
    }


    return 0;
}


bool Configuration::generateBufferSize()
{
    uint32_t seed = 0;
    FILE* rng = fopen("/dev/urandom", "rb");
    if (rng)
    {
        if (fread(&seed, sizeof(seed), 1, rng) < 1)
            seed = (uint32_t)time(0) ^ (uint32_t)getpid();
        fclose(rng);
    }
    else
    {
        seed = (uint32_t)time(0) ^ (uint32_t)getpid();
    }
    srand(seed);

    for (int i = 0; i <= MAX_PORTS; i++)
        portbuffermap.insert(make_pair(i, rand() % MAX_BUFFER_SIZE));

    return 0;
}


void Configuration::generateTimeouts()
{
    uint32_t seed = 0;
    FILE* rng = fopen("/dev/urandom", "rb");
    if (rng)
    {
        if (fread(&seed, sizeof(seed), 1, rng) < 1)
            seed = (uint32_t)time(0) ^ (uint32_t)getpid();
        fclose(rng);
    }
    else
    {
        seed = (uint32_t)time(0) ^ (uint32_t)getpid() ^ 0xdeadbeef;
    }
    srand(seed);

    if (tarpit_min > tarpit_max)
        tarpit_max = tarpit_min;

    for (int i = 0; i <= MAX_PORTS; i++)
    {
        /* spread across orders of magnitude: 10ms, 100ms, 1s, 10s+ */
        uint32_t base = 10;
        int shifts = rand() % 4;
        while (shifts-- > 0)
            base *= 10;
        uint32_t ms = base + rand() % (base * 9);

        if (ms < tarpit_min) ms = tarpit_min;
        if (ms > tarpit_max) ms = tarpit_max;
        port_timeouts[i] = ms;
    }
}


uint32_t Configuration::getPortTimeout(unsigned short port)
{
    if (port <= MAX_PORTS)
        return port_timeouts[port];
    return tarpit_min;
}


void Configuration::generateBehaviors()
{
    uint32_t seed = 0;
    FILE* rng = fopen("/dev/urandom", "rb");
    if (rng)
    {
        if (fread(&seed, sizeof(seed), 1, rng) < 1)
            seed = (uint32_t)time(0) ^ (uint32_t)getpid() ^ 0x1f2e3d4c;
        fclose(rng);
    }
    else
    {
        seed = (uint32_t)time(0) ^ (uint32_t)getpid() ^ 0x1f2e3d4c;
    }
    srand(seed);

    for (int i = 0; i <= MAX_PORTS; i++)
    {
        int roll = rand() % 100;
        if (roll < 60)
            port_behaviors[i] = BHVR_BANNER;
        else if (roll < 90)
            port_behaviors[i] = BHVR_WAIT;
        else
            port_behaviors[i] = BHVR_SILENT;
    }
}


uint8_t Configuration::getPortBehavior(unsigned short port)
{
    if (port <= MAX_PORTS)
        return port_behaviors[port];
    return BHVR_BANNER;
}


bool Configuration::readConfigFile()
{
    char tmp[BUFSIZE], str1[BUFSIZE], str2[BUFSIZE];
    int lp, hp;
    std::stringstream ss;


    FILE* fp = fopen(this->configfile.c_str(), "r");
    if (fp == NULL)
    {
        fprintf(stdout, "Error opening file: %s \n", this->configfile.c_str());
        return 1;
    }

    while (fgets(tmp, BUFSIZE, fp))
        if (strlen(tmp) > 1 && tmp[0] != '#')
        {
            if (sscanf(tmp, "%s %s", str1, str2) == EOF)
            {
                fprintf(stdout, "Error in configuration file");
                exit(1);
            }

            if (str1 == NULL || str2 == NULL)
            {
                fprintf(stdout, "Error in configuration file");
                exit(1);
            }

            if (Utils::isNumeric(str1)) //single port
            {
                sscanf(str1, "%d", &lp);

                portsignatureemap[lp] = process_signature(Utils::get_substring_value(tmp));
                continue;
            }
            else
            {
                if (sscanf(str1, "%d-%d", &lp, &hp) == EOF)
                {
                    fprintf(stdout, "Error in configuration file\n");
                    exit(1);
                }

                if (lp == 0 || hp == 0)
                {
                    fprintf(stdout, "Error in configuration file");
                    exit(1);
                }

                for (int i = lp; i <= hp; i++)
                    portsignatureemap[i] = process_signature(Utils::get_substring_value(tmp));

                continue;
            }
        }

    fclose(fp);


    return 0;
}