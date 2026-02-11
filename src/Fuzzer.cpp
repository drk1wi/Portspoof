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


#include "Fuzzer.h"

Fuzzer::Fuzzer()
{
    return;
}

Fuzzer::Fuzzer(Configuration* configuration)
{
    this->configuration = configuration;
    this->nmapfuzzsignatures_file = configuration->getNmapfuzzSignaturesFile();
    this->fuzzpayload_file = configuration->getFuzzPayloadFile();
    this->counter = 0;
    this->payload_counter = 0;
    this->PrepareFuzzer();

    return;
}


bool Fuzzer::PrepareFuzzer()
{
    if (this->configuration->getConfigValue(OPT_FUZZ_WORDLIST))
    {
        this->fp_payloads = fopen(this->fuzzpayload_file.c_str(), "r");
        if (this->fp_payloads == NULL)
        {
            fprintf(stdout, "Error opening payload file: %s \n", this->fuzzpayload_file.c_str());
            return 1;
        }
    }
    /////

    if (this->configuration->getConfigValue(OPT_FUZZ_NMAP))
    {
        std::ifstream file(this->nmapfuzzsignatures_file.c_str());
        if (!file.is_open())
        {
            fprintf(stdout, "Error opening nmap signature file: %s \n", this->nmapfuzzsignatures_file.c_str());
            return 1;
        }

        std::string line;
        while (getline(file, line))
        {
            this->nmapfuzzsignatures.push_back(line);
        }

        fprintf(stdout, "-> Nmap signatures read: %zu \n", this->nmapfuzzsignatures.size());

        return 0;
    }

    return 0;
}

std::vector<char> Fuzzer::intToBytes(int paramInt)
{
    vector<char> arrayOfByte(4);
    for (int i = 0; i < 4; i++)
        arrayOfByte[3 - i] = (paramInt >> (i * 8));
    return arrayOfByte;
}


std::vector<char> Fuzzer::shortToBytes(unsigned short paramInt)
{
    vector<char> arrayOfByte(2);
    for (int i = 0; i < 2; i++)
        arrayOfByte[1 - i] = (paramInt >> (i * 4));
    return arrayOfByte;
}

std::vector<char> Fuzzer::GenerateFuzzPayload()
{
    std::vector<char> result_vector;
    std::string str;


    if (this->configuration->getConfigValue(OPT_FUZZ_INTERNAL))
    {
        srand((unsigned)time(0));
        int size = rand() % 1000;

        for (int i = 0; i < size; i++)
            result_vector.push_back(rand() % 255);
        return result_vector;
    }


    if (this->payload_counter < 10)
    {
        for (int i = 0; i < 4000 * (this->payload_counter + 1); i++)
            result_vector.push_back(*(fuzz_oracle[0]));
    }
    else
    {
        str = std::string(fuzz_oracle[this->payload_counter - 9]);
        result_vector = Utils::str2vector(str);
    }

    this->payload_counter++;

    if (this->payload_counter >= 25)
        this->payload_counter = 0;

    return result_vector;
}

std::vector<char> Fuzzer::GetFUZZ()
{
    std::vector<char> result_vector;

    if (this->configuration->getConfigValue(OPT_FUZZ_WORDLIST))
    {
        if ((this->configuration->getConfigValue(OPT_FUZZ_NMAP) == 0) || this->counter % this->nmapfuzzsignatures.size()
            == 0)
        {
            char buf_file[BUFSIZE];
            std::string str;

            if (fgets(buf_file, BUFSIZE, this->fp_payloads) == NULL)
            {
                fprintf(stdout, "EOF of payload file\n");
                fflush(stdout);
            }

            str = std::string(buf_file);
            str.erase(str.size() - 1); //remove \n
            this->input_line = Utils::str2vector(str);
        }

        this->counter++;

        if (this->configuration->getConfigValue(OPT_FUZZ_NMAP) == 0)
            return this->input_line;
    }
    else if (this->configuration->getConfigValue(OPT_FUZZ_INTERNAL))
    {
        result_vector = this->GenerateFuzzPayload();
    }
    else
        fprintf(stdout, "Fuzz - shouldn't be here...\n");


    if (this->configuration->getConfigValue(OPT_FUZZ_NMAP))
    {
        if (this->configuration->getConfigValue(OPT_FUZZ_WORDLIST))
            result_vector = Utils::wrapNMAP(this->nmapfuzzsignatures[this->counter % this->nmapfuzzsignatures.size()],
                                            this->input_line);
        else if (this->configuration->getConfigValue(OPT_FUZZ_INTERNAL))
            result_vector = Utils::wrapNMAP(this->nmapfuzzsignatures[this->counter % this->nmapfuzzsignatures.size()],
                                            result_vector);

        result_vector = Utils::unescape(result_vector);
    }

    return result_vector;
}