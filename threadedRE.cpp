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
#include <vector>
#include <pthread.h>
#include <assert.h>

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
vector<FILE *> filevec;

pthread_mutex_t q_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t hash_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

/* PROTOTYPES --------------------------------------------------------------- */

void usage (int status);
void parse_data (char * filename);
void * producer(void * fn);
void parse_packet (FILE * fp);
void * consumer ( void * ); //FILE * fp);

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

    // thread handling
    if (thread_num == 1) {
        i = file_start;
        printf("File to process: ");
        for (; i < argc; i++)
        {
	    // Get file names
	    printf(" %s", argv[i]);
    	    parse_data(argv[i]);
        }
    } else if (thread_num > 1) {


        /*
        //vectors of pthreads
        int prod_num = (int) ceil(thread_num/2);
        int cons_num = (int) floor(thread_num/2);
        std::vector<pthread_t> producers(prod_num);
        std::vector<pthread_t> consumers(cons_num);

        for (vector<pthread_t>::iterator it = producers.begin(); it != producers.end(); it++) {
            int rc = create(&*it, NULL, producer, NULL?);
            assert(rc==0);
        }
        for (vector<pthread_t>::iterator jt = consumers.begin(); jt != consumers.end(); jt++) {
            rc = create(&*jt, NULL, consumer, NULL);
            assert(rc==0);
        }

        // join
        std::vector<pthread_t>::iterator pt = producers.begin();
        while (pt != producers.end()) {
            rc = pthread_join(*pt, NULL);
            assert(rc==0);
            pt++;
        }
        std::vector<pthread_t>::iterator ct = consumers.begin();
        while (ct != consumers.end()) {
            rc = pthread_join(*ct, NULL);
            assert(rc==0);
            ct++;
        }
*/
        pthread_t thread1;
        pthread_t thread2;
        i = file_start;
        printf("File to process: ");

        for (; i < argc; i++)
        {
	    // Get file names
	    printf(" %s", argv[i]);
	    char* arg = argv[i];
            
            // create
            int rc = pthread_create(&thread1, NULL, producer, (void *) arg);
            assert(rc==0);
            rc = pthread_create(&thread2, NULL, consumer, NULL);
            assert(rc==0);

            // join
            rc = pthread_join(thread1, NULL);
            assert(rc==0);
            rc = pthread_join(thread2, NULL);
        }
    } else {
        usage(1);
    }


    double redundancy = (double)hits / (double)npackets;
    redundancy = redundancy * 100.00;
    double mb = (double)ndata / 100000.00;

    // Output data
    printf("\n\nResults: \n");
    printf("%4.2f MB processed\n", mb);
    printf("%d hits\n", hits);
    printf("%4.2f%% redundancy detected\n\n", redundancy);
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

    // Call to parse_packet
    // TODO: collect packet data in a data structure
    parse_packet(file);
}

void * producer(void * fn) {
    char *filename;
    filename = (char *) fn;

    // copy of parse_data(), for use by threads
    FILE * file = fopen(filename, "rb");
    void* magic_number = malloc(4);
    void* snaplen = malloc(4);
    if(fread(&magic_number, 4, 1, file) < 4) { }
    
    fseek(file, 12, SEEK_CUR);
    if(fread(&snaplen, 4, 1, file) < 4) { }

    fseek(file, 4, SEEK_CUR);

    //consumer(file);
    pthread_mutex_lock( &q_mtx );
    filevec.push_back(file);
    pthread_cond_signal( &cv );
    pthread_mutex_unlock( &q_mtx );

    return NULL;
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


// Same as above - Parses all packets within a .pcap file
// but with threading
void * consumer( void * ) //void * fn) //FILE * fp)
{
    uint32_t packet_length;
    char packet_data[2400];
    FILE * fp;
    //fp = (FILE *) fn;

    // get file by locking queue/buffer
    pthread_mutex_lock( &q_mtx );
    pthread_cond_wait( &cv, &q_mtx );
    // pop
    fp = filevec.front();
    filevec.erase(filevec.begin());
    pthread_mutex_unlock( &q_mtx );
   
    // lock for hash
    pthread_mutex_lock( &hash_mtx );
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
    pthread_mutex_unlock( &hash_mtx );

    return NULL;
}
