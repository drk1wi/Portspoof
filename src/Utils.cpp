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


#include "Utils.h"


pthread_cond_t log_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


void Utils::hexdump(void* mem, unsigned int len)
{
    unsigned int i, j;

    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
        {
            fprintf(stdout, "0x%06x: ", i);
        }

        /* print hex data */
        if (i < len)
        {
            fprintf(stdout, "%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            fprintf(stdout, "   ");
        }

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if (j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if (isprint(((char*)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char*)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

std::vector<char> Utils::wrapNMAP(string wrapper, std::vector<char> payload)
{
    stringstream ss;
    string str;
    std::vector<char> result_vector;

    ss << wrapper.substr(0, wrapper.find(FUZZING_KEYWORD));
    str = ss.str();

    for (unsigned int i = 0; i < str.length(); i++)
        result_vector.push_back(str[i]);

    result_vector.insert(result_vector.end(), payload.begin(), payload.end());

    ss.str("");
    ss << wrapper.substr(wrapper.find(FUZZING_KEYWORD) + strlen(FUZZING_KEYWORD), wrapper.size());

    str = ss.str();

    for (unsigned int i = 0; i < str.length(); i++)
        result_vector.push_back(str[i]);

    return result_vector;
}

std::vector<char> Utils::str2vector(std::string& s)
{
    std::vector<char> result_vector;

    for (int i = 0; i < s.length(); i++)
        result_vector.push_back(s[i]);

    return result_vector;
}

int Utils::isNumeric(const char* s)
{
    if (s == NULL || *s == '\0' || isspace(*s))
        return 0;
    char* p;
    strtod(s, &p);
    return *p == '\0';
}


std::vector<char> Utils::unescape(std::vector<char>& s)
{
    std::vector<char> res;
    vector<char>::const_iterator it = s.begin();
    while (it != s.end())
    {
        char c = *it++;
        if (c == '\\' && it != s.end())
        {
            switch (*it++)
            {
            case 'n': c = '\n';
                break;
            case 'r': c = '\r';
                break;
            case 't': c = '\t';
                break;

            // all other escapes
            default:
                // invalid escape sequence - skip it. alternatively you can copy it as is, throw an exception...
                continue;
            }
        }
        res.push_back(c);
    }

    return res;
}


std::string Utils::get_substring_value(char* str)
{
    int i = 0;
    int soffset = -1, eoffset = -1;
    for (i; i < strlen(str); i++)
    {
        if (str[i] == '"')
        {
            if (soffset == -1)
                soffset = i;
            else if (eoffset == -1)
            {
                eoffset = i;
                break;
            }
            else
            {
                fprintf(stdout, "Error in configuration file1");
                exit(1);
            }
        }
    }

    if (soffset == -1 || eoffset == -1)
    {
        fprintf(stdout, "Error in configuration file2");
        exit(1);
    }

    return std::string(str + soffset + 1, eoffset - soffset - 1);
}


void Utils::log_create(const char* file)
{
    FILE* fp = fopen(file, "a");
    if (fp == NULL)
    {
        fp = fopen(file, "w");
    }
    fclose(fp);
    return;
}

void Utils::log_write(Configuration* configuration, const char* msg)
{
    pthread_mutex_lock(&log_mutex);

    if (configuration->getConfigValue(OPT_LOG_FILE))
    {
        FILE* fp = fopen(configuration->getLogFile().c_str(), "a");
        if (fp == NULL)
        {
            pthread_mutex_unlock(&log_mutex);
            return;
        }

        fprintf(fp, "%s", msg);
        fclose(fp);
    }

    if (!(configuration->getConfigValue(OPT_SYSLOG_DIS)))
    {
        openlog(SYSLOG_NAME, LOG_PID | LOG_CONS, LOG_USER);
        syslog(LOG_INFO, " %s", msg);
        closelog();
    }
    pthread_mutex_unlock(&log_mutex);

    return;
}


void Utils::daemonize(Configuration* configuration)
{
    const string& dir = "/";
    const std::string& stdinfile = "/dev/null";
    const std::string& stdoutfile = "/dev/null";
    const std::string& stderrfile = "/dev/null";


    umask(0);


    rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
    {
        throw std::runtime_error(strerror(errno));
    }


    pid_t pid;
    if ((pid = fork()) < 0)
    {
        throw std::runtime_error(strerror(errno));
    }
    else if (pid != 0)
    {
        //parent
        exit(0);
    }


    setsid();

    if (!dir.empty() && chdir(dir.c_str()) < 0)
    {
        throw std::runtime_error(strerror(errno));
    }


    if (setgid(configuration->getGroupid()) != 0)
    {
        fprintf(stdout, "setgid: Unable to drop group privileges: %s", strerror(errno));
        fflush(stdout);
        exit(-1);
    }


    if (setuid(configuration->getUserid()) != 0)
    {
        fprintf(stdout, "setuid: Unable to drop user privileges: %s", strerror(errno));
        fflush(stdout);
        exit(-1);
    }


    if (rl.rlim_max == RLIM_INFINITY)
    {
        rl.rlim_max = 1024;
    }

    for (unsigned int i = 0; i < rl.rlim_max; i++)
    {
        close(i);
    }


    int fd0 = open(stdinfile.c_str(), O_RDONLY);
    int fd1 = open(stdoutfile.c_str(),
                   O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    int fd2 = open(stderrfile.c_str(),
                   O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);


    if (fd0 != STDIN_FILENO || fd1 != STDOUT_FILENO || fd2 != STDERR_FILENO)
    {
        throw runtime_error("new standard file descriptors were not opened as expected");
    }
}