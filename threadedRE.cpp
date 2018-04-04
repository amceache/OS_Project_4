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
#include <math.h>

#include "hashtable.h"

using namespace std;

/* GLOBALS ------------------------------------------------------------------ */

#define HASH_SIZE 20000

char * PROGRAM_NAME;
hash<string> hash_fn; // Hash function called on strings
list<string> hashtble[HASH_SIZE]; // Array to hold hash values
int hits;
int npackets;
int nstored;
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
    // check level validity
    int level;
    if (strcmp(argv[2],"1") == 0 || strcmp(argv[2],"2") == 0) {
        level = stoi(argv[2]);
    } else {
	printf("ERROR: Improper usage\n");
	usage(1);
    } 
    int thread_num, file_start, i;
    hits = 0;
    npackets = 0;
    nstored = 0;
    ndata = 0;

    if (strcmp(argv[3], "-thread") != 0)
    {
	// Default thread_num
	thread_num = 1;   
	file_start = 3;
    }
    else
    { // make sure thread_num is an int
	try {
	thread_num = stoi(argv[4]);
	} catch (...) {
	    printf("ERROR: Improper usage\n");
	    usage(1);
	}
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

	int running_threads=0;
	int repeat=0;
	// producer thread
	 pthread_t thread_prod;
        int cons_num = thread_num - 1;

	printf("Allocating 1 thread to file I/O, %d threads to processing\n", cons_num);
        printf("Files to process: ");
	
        if (cons_num > argc - file_start) {
            cons_num = argc - file_start;
        } else if (cons_num < argc - file_start) {
            repeat = (int) ceil((argc-file_start)/cons_num);
        }

        while (repeat >= 0) {
            if (repeat == 0) {
                cons_num = argc - file_start;
            }
            // consumer vector
            std::vector<pthread_t> consumers(cons_num);
            // producer thread
            i=0;
            while (i<cons_num && i+file_start < argc) {
                printf(" %s", argv[i+file_start]);
                char* arg = argv[i+file_start];
                int rc = pthread_create(&thread_prod, NULL, producer, (void *) arg);
                assert(rc==0);
                i++;
            }
            file_start += i;

            // consumer threads
            for (vector<pthread_t>::iterator jt = consumers.begin(); jt != consumers.end(); jt++) {
                int rc = pthread_create(&*jt, NULL, consumer, NULL);
                running_threads++;
                assert(rc==0);
            }

            // join consumers
            std::vector<pthread_t>::iterator ct = consumers.begin();

            while (ct != consumers.end()) {
                int rc = pthread_join(*ct, NULL);
                assert(rc==0);
                ct++;
                running_threads--;
            }
            repeat--;
        }
        // producer
        int rc = pthread_join(thread_prod, NULL);
        assert(rc==0);
        running_threads--;

    } else {
	usage(1);
    }

    if (ndata == 0)
    {
	printf("\n\nNo valid files to read.\n");
	return EXIT_FAILURE;
    }

    double redundancy = (double)hits / (double)npackets;
    redundancy = redundancy * 100.00;
    double mb = (double)ndata / 1000000.00;
    // double storedmb = (double)nstored / 1000000.00;

    // Output data
    printf("\n\nResults: \n");
    printf("%4.2f MB processed\n", mb);
    // printf("%4.2f MB stored in hash table\n", storedmb);
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
    // check file type
    if (strstr(filename, ".pcap")) {
	fprintf(stderr, "ERROR: %s - Invalid File\n", filename);
        return;
    }

    FILE * file = fopen(filename, "rb"); // open .pcap file
    if (file == NULL)
    {
	// fopen failed
	fprintf(stderr, "ERROR: %s - Invalid File\n", filename);
	return;
    }
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

// copy of parse_data(), for use by threads
void * producer(void * fn) {
    char *filename;
    filename = (char *) fn;

    // check file type
    if (strstr(filename, ".pcap")) {
	fprintf(stderr, "ERROR: %s - Invalid File\n", filename);
	exit(1);
    }

    FILE * file = fopen(filename, "rb");
    if (file == NULL)
    {
	// fopen failed
	fprintf(stderr, "ERROR: %s - Invalid File\n", filename);
	exit(1);
    }
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
    char rand_char[10];

    while(fread(&rand_char, 8, 1, fp) != 0)
    {
	//fseek(fp, 8, SEEK_CUR); // Increment past timestamps
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
	    nstored = nstored + packet_length;
	    
	    if (nstored > 64*1000000)
	    {
		// Stored data exceeds limit, eliminate data point
		int r = rand() % HASH_SIZE;
		while(hashtble[r].empty())
		{   // continue looking for element to delete
		    r = rand() % HASH_SIZE;
		}
		string s = hashtble[r].front();
		nstored = nstored - s.size();
		// printf("nstored: %d\n", nstored);
		hashtble[r].pop_front();
	    }

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
void * consumer( void * ) 
{
    uint32_t packet_length;
    char packet_data[2400];
    char rand_char[10];
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
    while(fread(&rand_char, 8, 1, fp) != 0)
    {
	// fseek(fp, 8, SEEK_CUR); // Increment past timestamps
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
	    nstored = nstored + packet_length;
	    
	    if (nstored > 64*1000000)
	    {
		// Stored data exceeds limit, eliminate data point
		int r = rand() % HASH_SIZE;
		while(hashtble[r].empty())
		{   // continue looking for element to delete
		    r = rand() % HASH_SIZE;
		}
		string s = hashtble[r].front();
		nstored = nstored - s.size();
		// printf("nstored: %d\n", nstored);
		hashtble[r].pop_front();
	    }

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
