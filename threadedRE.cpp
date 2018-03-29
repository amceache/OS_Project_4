// threadedRE.cpp
/* ************************************************************************** *
 * 25 Mar 2018
 *
 *
 *
 * ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <list>
#include <string>
#include <functional>

#include "hashtable.h"

using namespace std;

/* GLOBALS ------------------------------------------------------------------ */

#define HASH_SIZE 20000

char * PROGRAM_NAME;
hash<string> hash_fn; // Hash function called on strings
list<string> hashtble[HASH_SIZE]; // Array to hold hash values
int hits;
int npackets;
int ndata;

/* PROTOTYPES --------------------------------------------------------------- */

void usage (int status);
void parse_data (char * filename);
void parse_packet (FILE * fp);

/* MAIN --------------------------------------------------------------------- */

int main (int argc, char * argv[])
{
    PROGRAM_NAME = argv[0];
    
    printf("Welcome to Project 4 - ThreadedRE\n");
    if (argc < 4)
    {
	// Not enough arguments
	usage(1);
    }
    if (strcmp(argv[1], "-level") != 0)
    {
	printf("ERROR: Improper usage\n");
	usage(1);
    }
    int level = atoi(argv[2]);
    int thread_num, file_start, i;
    hits = 0;
    npackets = 0;
    ndata = 0;

    if (strcmp(argv[3], "-thread") != 0)
    {
	// Default thread_num
	thread_num = 1;   
	file_start = 3;
    }
    else
    {
	thread_num = atoi(argv[4]);
	file_start = 5;
    }

    // Arguments 3+ (if no thread specified) or 5+ (if thread specified)
    // contain the filenames, file_start tells which argument to begin with
    printf("Now operating in Level %d mode\n", level);
    printf("Threads Allowed: %d\n", thread_num);

    // Init hashtable
    
    i = file_start;
    printf("File to process: ");
    for (; i < argc; i++)
    {
	// Get file names
	printf(" %s", argv[i]);
	parse_data(argv[i]);
    }

    double redundancy = (double)hits / (double)npackets;
    redundancy = redundancy * 100.00;
    double mb = (double)ndata / 100000.00;

    // Output data
    printf("\n\nResults: \n");
    printf("%f.2 MB processed\n", mb);
    printf("%d hits\n", hits);
    printf("%f.2%% redundancy detected\n\n", redundancy);
    return EXIT_SUCCESS;
}

/* FUNCTIONS ---------------------------------------------------------------- */

void usage(int status)
{
    printf("USAGE: %s -level [LEVEL] -thread [THREAD_NUM] [FILES]\n", PROGRAM_NAME);
    printf("   LEVEL      - level to run threadedRE\n");
    printf("   THREAD_NUM - number of threads\n");
    printf("   FILES      - .pcap files to process\n");
    exit(status);
}

// Parses global header of .pcap and calls parse_packet
void parse_data(char * filename)
{
    FILE * file = fopen(filename, "rb"); // open .pcap file
    uint32_t magic_number;
    uint32_t snaplen;
    if(fread(&magic_number, 4, 1, file) < 4)
    {
	// Error reading data
    }

    fseek(file, 12, SEEK_CUR); // Incrememnt to start of snaplen
    if(fread(&snaplen, 4, 1, file) < 4)
    {
	// Error reading data
    }

    fseek(file, 4, SEEK_CUR); // Increment to packet header

    // printf("magic number = %X\nsnaplen = %d\n", magic_number, snaplen);
    // Call to parse_packet
    // TODO: collect packet data in a data structure
    parse_packet(file);
}

// Parses all packets within a .pcap file
void parse_packet(FILE * fp)
{
    uint32_t packet_length;
    char packet_data[2400];
    
    while(!feof(fp))
    {
	fseek(fp, 8, SEEK_CUR); // Increment past timestamps
	fread(&packet_length, 4, 1, fp);
	fseek(fp, 4, SEEK_CUR); // Increment to packet data

	// Check packet length
	if(packet_length < 128)
	{
	    // Ignore packets of less that 128 bytes
	    fseek(fp, packet_length, SEEK_CUR);
	}
	else if(packet_length < 2400)
	{
	    npackets++;
	    
	    // skip 52 bytes into packet payload (not hashed)
	    fseek(fp, 52, SEEK_CUR);
	    packet_length = packet_length - 52;
	    ndata = ndata + packet_length;

	    // read packet data
	    fread(packet_data, 1, packet_length, fp);
	    // printf("Read packet of length %d\n", packet_length);
	
	    // convert to std::string
	    string str;
	    str.assign(packet_data, packet_length);
	
	    // compute the hash value of the string
	    size_t hash_val = hash_fn(str);

	    // critical section for hashtbl - add new value to table
	    if (hashtble[hash_val % HASH_SIZE].empty())
	    {
		// hash not been matched before
		hashtble[hash_val % HASH_SIZE].push_back(str);
	    }
	    else
	    {
		// compare str to every element in list
		bool match = false;
		for (string s : hashtble[hash_val % HASH_SIZE])
		{
		    // compare s with str, if match, increment hits
		    if (s == str)
		    {
			match = true;
			hits++;
			break;
		    }
		}
		
		// add element to list if there was not match
		if (!match)
		{
		    hashtble[hash_val % HASH_SIZE].push_back(str);
		}
	    }
	}
	else
	{
	    // Packet is too long
	    fseek(fp, packet_length, SEEK_CUR);
	}
	// Read packet and moved to next one at this point
    }
}
