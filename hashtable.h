#ifndef HASHTABLE_H
#define HASHTABLE_H

/* STRUCTS ------------------------------------------------------------------ */

struct packet
{
    size_t hash; // Hash function of the data created by hash_fn
    char * packet_data;
};

typedef struct packet entry_t;

struct table
{
    int size;
    struct packet ** table;
};

typedef struct table hashtable_t;

/* PROTOTYPES --------------------------------------------------------------- */

hashtable_t * createTable (int size);
int generateHash (hashtable_t * hashtable, char * packet_header);
entry_t * newNode (char * packet_header, char * packet_data);
void insert (hashtable_t * hashtable, char * packet_header, char * packet_data);
char * lookup (hashtable_t * hashtable, char * packet_header);

#endif
