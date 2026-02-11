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


using namespace std;
typedef vector<char> wektor;


wektor str2vector(string s)
{
    wektor result_vector;
    for (int i = 0; i < s.length(); i++)
        result_vector.push_back(s[i]);

    return result_vector;
}

wektor cutvector(wektor str, int start_offset, int end_offset)
{
    wektor result_vector;
    for (int i = start_offset; i <= end_offset; i++)
        result_vector.push_back(str[i]);


    return result_vector;
}

wektor mergevector(wektor str1, wektor str2)
{
    wektor result_vector;

    for (int i = 0; i < str1.size(); i++)
        result_vector.push_back(str1[i]);

    for (int i = 0; i < str2.size(); i++)
        result_vector.push_back(str2[i]);

    return result_vector;
}

void revregx_error(wektor& regex)
{
    fprintf(stdout, "Regex error : !!");
    for (int k = 0; k < regex.size(); k++)
        cout << regex[k];
    cout << endl;
}

void print_vector(wektor& wektor, int s, int e)
{
    int sf = s;
    int ef = e;
    for (int k = sf; k < ef; k++)
        cout << wektor[k];
    cout << endl;
}

int char2hex(char hb, char lb) //set to 2 chars
{
    unsigned int value = 0;
    char ch = hb;
    int i = 2;

    while (i--)
    {
        if (ch >= '0' && ch <= '9')
            value = (value << 4) + (ch - '0');
        else if (ch >= 'A' && ch <= 'F')
            value = (value << 4) + (ch - 'A' + 10);
        else if (ch >= 'a' && ch <= 'f')
            value = (value << 4) + (ch - 'a' + 10);
        else
            return value;
        ch = lb;
    }

    return value;
}

int ishex(char val)
{
    if (val >= '0' && val <= '9')
        return 1;
    else if (val >= 'A' && val <= 'F')
        return 1;
    else if (val >= 'a' && val <= 'f')
        return 1;
    else
        return 0;
}

wektor revregex_process_bracket(wektor str, int start_offset, int end_offset) //index: '[' ... ']' 
{
    wektor result_vector;
    //TODO hex support
    int bslash = '\\';
    int word = 'w';
    int digit = 'd';
    int range = '-';

    //flags
    char nnot = 0;
    char wordf = 0;
    char digitf = 0;
    char rangeword = 0;
    char rangedigit = 0;

    //character pool
    char characters[256] = {0,};
    int chari = 0;
    char characterstmp[256] = {0,};
    long character_class = 0;

    //skip first bracket char
    int i = start_offset + 1;
    int lend_offset = end_offset;
    int tmpj;

    if (str[i] == '^') //not flag
    {
        i++;
        nnot = 1;
    }

    // DEBUG
    //fprintf(stdout,"Start off:%d  End off:%d\n",i,end_offset);
    //print_vector(str,i,end_offset);

    for (i; i < lend_offset; i++)
    {
        if (str[i] == bslash && i + 1 != lend_offset) //special chars - check if character class
        {
            if (str[i + 1] == 'c')
                character_class |= 1 << 1;
            else if (str[i + 1] == 's')
                character_class |= 2 << 1;
            else if (str[i + 1] == 'S')
                character_class |= 1 << 3;
            else if (str[i + 1] == 'd')
                character_class |= 1 << 4;
            else if (str[i + 1] == 'D')
                character_class |= 1 << 5;
            else if (str[i + 1] == 'w')
                character_class |= 1 << 6;
            else if (str[i + 1] == 'W')
                character_class |= 1 << 7;
            else if (str[i + 1] == 'n')
                characters['\n'] = 1;
            else if (str[i + 1] == 'r')
                characters['\r'] = 1;
            else if (str[i + 1] == 't')
                characters['\t'] = 1;
            else if (str[i + 1] == 'v')
                characters['\v'] = 1;
            else if (str[i + 1] == 'f')
                characters['\f'] = 1;
            else if (str[i + 1] == '0')
                characters['\0'] = 1;
            else
            {
                //DEBUG
                //fprintf(stdout,"unknown char: %c !\n", str[i+1]); //DEBUG - ignore this char it probably was escaped
                characters[(unsigned char)str[i + 1]] = 1;
            }
            i++;
        }
        else if (isalpha(str[i]) && (i + 1) != lend_offset && str[i + 1] == range && (i + 2) != lend_offset &&
            isalpha(str[i + 2])) //check if rangeword
        {
            //DEBUG
            //fprintf(stdout,"rangew");

            //add chars from range to the pool
            tmpj = (unsigned char)str[i];
            for (tmpj; tmpj <= (unsigned char)str[i + 2]; tmpj++)
            {
                characters[tmpj] = 1;
            }
            i += 3;
            rangeword = 1;
        }
        else if (isdigit(str[i]) && (i + 1) != lend_offset && str[i + 1] == range && (i + 2) != lend_offset &&
            isdigit(str[i + 2])) //check if rangedigit
        {
            //DEBUG
            //fprintf(stdout,"ranged");

            tmpj = (unsigned char)str[i];
            for (tmpj; tmpj <= (unsigned char)str[i + 2]; tmpj++)
            {
                characters[tmpj] = 1;
            }
            i += 3;
            rangedigit = 1;
        }
        else if (str[i] == '.')
            character_class |= 1 << 8;
        else if (str[i] == '|') //TODO: implement this
            character_class |= 1 << 9;
        else
        {
            //printf ("# [ char %c ]\n",str[i]);
            characters[(unsigned char)str[i]] = 1;
        }
    }

    char endmetachar = str[end_offset + 1]; //TODO: should be ok unless one creates "[a-z]", which is invalid regex!
    int finsize = 0;
    //srand (time(NULL) );

    // fill character pool
    if (character_class & 1 << 1)
    {
    }
    else if (character_class & 1 << 2)
    {
    }
    else if (character_class & 1 << 3)
    {
    }
    else if (character_class & 1 << 4)
    {
        int j = '0';
        for (j; j <= '9'; j++)
        {
            characters[j] = 1;
        }
    }
    else if (character_class & 1 << 5)
    {
    }
    else if (character_class & 1 << 6)
    {
        int j = 'a';
        for (j; j <= 'z'; j++)
        {
            characters[j] = 1;
        }

        j = 'A';
        for (j; j <= 'Z'; j++)
        {
            characters[j] = 1;
        }
    }
    else if (character_class & 1 << 7)
    {
    }
    else if (character_class & 1 << 8)
    {
        /*
		int j=0;
		for(j;j<255;j++)
		{
			characters[j]=1;
		}
		
		characters['\n']=0;
		*/
    }
    else if (character_class & 1 << 9)
    {
    }

    // simple support - TODO to extend
    if (endmetachar == '*')
        finsize = rand() % 10;
    else if (endmetachar == '+')
        finsize = 1 + rand() % 9;


    // DEBUG f
    //fprintf(stdout,"\n###\n");


    //TODO to be corrected
    i = 0;
    for (i; i < 256; i++)
    {
        if (nnot == 0 && characters[i])
        {
            if ((i == '[') || (i == ']'))
                continue;

            characterstmp[chari] = i;
            chari++;
            //fprintf(stdout,"%c",i);
        }
        else if (nnot && characters[i] == 0)
        {
            if ((i == '[') || (i == ']'))
                continue;
            characterstmp[chari] = i;
            chari++;
        }
    }

    if (chari)
    {
        int tmp;
        i = 0;

        for (i; i < finsize; i++)
        {
            tmp = rand() % chari;
            result_vector.push_back(characterstmp[tmp]);
        }
    }

    return result_vector;
}

wektor fill_specialchars(wektor str, int start_offset, int end_offset)
{
    int bslash = '\\';
    int word = 'w';
    int digit = 'd';
    int dot = '.';
    int newline = 'n';
    int creturn = 'r';
    int tab = 't';

    wektor result_vector;

    int i = start_offset;

    for (i; i <= end_offset; i++)
    {
        if (str[i] == bslash && i + 1 <= end_offset && str[i + 1] == word && (i == start_offset || str[i - 1] !=
            bslash))
        {
            result_vector.push_back(97 + rand() % 25);
            i++;
            if (i + 1 <= end_offset && (str[i + 1] == '+' || str[i + 1] == '*'))
                i += 2;
        }
        else if (str[i] == bslash && i + 1 <= end_offset && str[i + 1] == digit && (i == start_offset || str[i - 1] !=
            bslash))
        {
            result_vector.push_back(48 + rand() % 10);
            i++;

            if (i + 1 <= end_offset && (str[i + 1] == '+' || str[i + 1] == '*'))
                i = i + 2;
        }
        else if (str[i] == bslash && i + 1 <= end_offset && str[i + 1] == newline && (i == start_offset || str[i - 1] !=
            bslash))
        {
            result_vector.push_back('\n');
            i++;
        }
        else if (str[i] == bslash && i + 1 <= end_offset && str[i + 1] == creturn && (i == start_offset || str[i - 1] !=
            bslash))
        {
            result_vector.push_back('\r');
            i++;
        }
        else if (str[i] == bslash && i + 1 <= end_offset && str[i + 1] == tab && (i == start_offset || str[i - 1] !=
            bslash))
        {
            result_vector.push_back('\t');
            i++;
        }
        else if (str[i] == dot && i + 1 <= end_offset && (i == start_offset || str[i - 1] != bslash))
        {
            result_vector.push_back(97 + rand() % 25);
            if (i <= end_offset && (str[i + 1] == '+' || str[i + 1] == '*'))
                i++;
        }
        else
            result_vector.push_back(str[i]);
    }

    return result_vector;
}

wektor escape_hex(wektor str, int start_offset, int end_offset)
{
    wektor result_vector;
    int bslash = '\\';

    int i = start_offset;

    for (i; i <= end_offset; i++)
    {
        if (str[i] == bslash && (i == start_offset || str[i - 1] != bslash))
        {
            if (str[i + 1] == 'x' && i + 2 != end_offset + 1 && ishex(str[i + 2]) && i + 3 != end_offset + 1 &&
                ishex(str[i + 3]))
            {
                result_vector.push_back(char2hex(str[i + 2], str[i + 3]));
                i += 3;
            }
        }
        else
            result_vector.push_back(str[i]);
    }

    return result_vector;
}


wektor revregexn(wektor str)
{
    //defines
    char lnaw = '(';
    char rnaw = ')';
    char lbrak = '[';
    char rbrak = ']';
    char bslash = '\\';
    bool isinbracketi = false;
    bool isinbracketj = false;
    bool isescapedi = false;
    bool isescapedj = false;

    std::vector<char> result_vector = str;
    std::vector<char> tmp;

repeat_remove:
    tmp.clear();
    isinbracketi = false;
    isescapedi = false;

    //cout<<"start1: \n";
    //print_vector(result_vector,0,result_vector.size());

    for (int i = 0; i < result_vector.size(); i++) // remove parenthises
    {
        if (result_vector[i] == lbrak && i - 1 >= 0 && result_vector[i - 1] != bslash)
            isinbracketi = true;
        if (result_vector[i] == rbrak && result_vector[i - 1] != bslash)
            isinbracketi = false;

        if (result_vector[i] == bslash)
            isescapedi = !isescapedi;
        else
            isescapedi = false;


        if (result_vector[i] == lnaw && !isinbracketi && (i == 0 || result_vector[i - 1] != bslash) && !isescapedi)
        {
            isinbracketj = false;
            isescapedj = isescapedi;

            for (int j = i; j < result_vector.size();)
            {
                if (result_vector[j] == lbrak && j - 1 >= 0 && result_vector[j - 1] != bslash)
                    isinbracketj = true;
                if (result_vector[j] == rbrak && result_vector[j - 1] != bslash)
                    isinbracketj = false;

                if (result_vector[j] == bslash)
                    isescapedj = !isescapedj;
                else
                    isescapedj = false;


                if (result_vector[j] == rnaw && !isinbracketi && !isinbracketj && !isescapedj)
                {
                    tmp = mergevector(tmp, cutvector(result_vector, 0, i - 1));
                    tmp = mergevector(tmp, cutvector(result_vector, i + 1, j - 1));
                    tmp = mergevector(tmp, cutvector(result_vector, j + 1, result_vector.size() - 1));
                    result_vector = tmp;
                    goto repeat_remove;
                }

                j++;

                /*
				if(j==result_vector.size())
				{

				if(configuration->getConfigValue(OPT_DEBUG))
				revregx_error(result_vector);

				}
				*/
            }
        }
        else if (result_vector[i] == rnaw && i > 0 && result_vector[i - 1] != bslash && !isinbracketi)
        {
            /*
			if(configuration->getConfigValue(OPT_DEBUG))
			revregx_error(result_vector);
			*/
        }
    }


repeat_remove2:
    tmp.clear();
    isescapedi = false;
    //cout<<"start2: \n";
    //print_vector(result_vector,0,result_vector.size());
    wektor tmpwekt;
    for (int i = 0; i < result_vector.size(); i++) // remove brackets
    {
        if (result_vector[i] == bslash)
            isescapedi = !isescapedi;
        else
            isescapedi = false;

        if (result_vector[i] == lbrak && ((i == 0) || result_vector[i - 1] != bslash) && !isescapedi)
        {
            isescapedj = isescapedi;

            for (int j = i; j < result_vector.size();)
            {
                if (result_vector[j] == bslash)
                    isescapedj = !isescapedj;
                else
                    isescapedj = false;

                if (result_vector[j] == rbrak && !isescapedj)
                {
                    //cout<<i<<" "<<j<<endl;
                    tmpwekt = revregex_process_bracket(result_vector, i, j);
                    tmp = mergevector(tmp, cutvector(result_vector, 0, i - 1));
                    tmp = mergevector(tmp, tmpwekt);
                    tmp = mergevector(tmp, cutvector(result_vector, j + 2, result_vector.size() - 1));
                    result_vector = tmp;
                    goto repeat_remove2;
                }

                j++;

                /*
				if(j==result_vector.size())
				{
				revregx_error(result_vector);
				}
				*/
            }
        }
    }


    return result_vector;
}


std::vector<char> process_signature(std::string str)
{
    std::vector<char> result_vector;

    try
    {
        result_vector = revregexn(str2vector(str));
        result_vector = fill_specialchars(result_vector, 0, result_vector.size() - 1);
        result_vector = escape_hex(result_vector, 0, result_vector.size() - 1);
    }
    catch (...)
    {
        cout << "Fatal error occured while processing signatures. Plz. open a github ticker for following regex:" <<
            endl;
        cout << str << endl;
        exit(1);
    }

    return result_vector;
}