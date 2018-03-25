#define _XOPEN_SOURCE 500 /* Enable certain library functions (strdup) on linux.  See feature_test_macros(7) */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

struct packet {
	char *packet_header;
	char *packet_data;
    int frequency; 
	struct packet *next;
};

typedef struct packet entry_t;

struct table {
	int size;
	struct packet **table;	
};

typedef struct table hashtable_t;


/* Create a new hashtable. */
hashtable_t *createTable( int size ) {

	hashtable_t *hashtable = NULL;
	int i;

	if( size < 1 ) return NULL;

	/* Allocate the table itself. */
	if( ( hashtable = malloc( sizeof( hashtable_t ) ) ) == NULL ) {
		return NULL;
	}

	/* Allocate pointers to the head nodes. */
	if( ( hashtable->table = malloc( sizeof( entry_t * ) * size ) ) == NULL ) {
		return NULL;
	}
	for( i = 0; i < size; i++ ) {
		hashtable->table[i] = NULL;
	}

	hashtable->size = size;

	return hashtable;	
}

/* Hash a string for a particular hash table. */
int generateHash( hashtable_t *hashtable, char *packet_header ) {

	unsigned long int hashval;
	int i = 0;

	/* Convert our string to an integer */
	while( hashval < ULONG_MAX && i < strlen( packet_header ) ) {
		hashval = hashval << 8;
		hashval += packet_header[ i ];
		i++;
	}

	return hashval % hashtable->size;
}

/* Create a packet_header-packet_data packet_node. */
entry_t *newNode( char *packet_header, char *packet_data ) {
	entry_t *newpacket_node;

	if( ( newpacket_node = malloc( sizeof( entry_t ) ) ) == NULL ) {
		return NULL;
	}

	if( ( newpacket_node->packet_header = strdup( packet_header ) ) == NULL ) {
		return NULL;
	}

	if( ( newpacket_node->packet_data = strdup( packet_data ) ) == NULL ) {
		return NULL;
	}

	newpacket_node->next = NULL;

	return newpacket_node;
}

// Insert a packet_header-packet_data packet_node into a hash table
void insert( hashtable_t *hashtable, char *packet_header, char *packet_data ) {
	int loc = 0;
	entry_t *newpacket_node = NULL;
	entry_t *next = NULL;
	entry_t *last = NULL;

    //This is the hash value. Use it to compare nodes 
	loc = generateHash( hashtable, packet_header );

	next = hashtable->table[ loc ];

	while( next != NULL && next->packet_header != NULL && strcmp( packet_header, next->packet_header ) > 0 ) {
		last = next;
		next = next->next;
	}

	//There already is a node 
	if( next != NULL && next->packet_header != NULL && strcmp( packet_header, next->packet_header ) == 0 ) {
        printf("There is a collsion\n"); 
        next->frequency = next->frequency + 1;
        printf("%d\n", next->frequency); 

	//Node doesnt exist, make one 
	} else {
		newpacket_node = newNode( packet_header, packet_data );

		//Find where we are in the list 
		if( next == hashtable->table[ loc ] ) {
			newpacket_node->next = next;
			hashtable->table[ loc ] = newpacket_node;
	
		//End of list 
		} else if ( next == NULL ) {
			last->next = newpacket_node;
	
		//Middle of list 
		} else  {
			newpacket_node->next = next;
			last->next = newpacket_node;
		}
	}
}

//Find the node based on header 

char *lookup( hashtable_t *hashtable, char *packet_header )
 {
	int loc = 0;
	entry_t *packet_node;

	loc = generateHash( hashtable, packet_header );

	//Search for data 
	packet_node = hashtable->table[ loc ];
	while( packet_node != NULL && packet_node->packet_header != NULL && strcmp( packet_header, packet_node->packet_header ) > 0 ) {
		packet_node = packet_node->next;
	}

	//Was anything found 
	if( packet_node == NULL || packet_node->packet_header == NULL || strcmp( packet_header, packet_node->packet_header ) != 0 ) {
		return NULL;

	} else {
		return packet_node->packet_data;
	}
	
}


int main( int argc, char **argv ) {

	hashtable_t *hashtable = createTable( 65536 );

	insert( hashtable, "packet_header1", "packet_data1" );
	insert( hashtable, "packet_header2", "packet_data2" );
	insert( hashtable, "packet_header3", "packet_data3" );
	insert( hashtable, "packet_header4", "packet_data4" );
        insert( hashtable, "packet_header2", "packet_data2" );
        insert( hashtable, "packet_header2", "packet_data2" );
        insert( hashtable, "packet_header2", "packet_data2" );

	printf( "%s\n", lookup( hashtable, "packet_header1" ) );
	printf( "%s\n", lookup( hashtable, "packet_header2" ) );
	printf( "%s\n", lookup( hashtable, "packet_header3" ) );
	printf( "%s\n", lookup( hashtable, "packet_header4" ) );

	return 0;
}

