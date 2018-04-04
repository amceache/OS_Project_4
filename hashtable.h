#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <string>

using namespace std;

/* STRUCTS ------------------------------------------------------------------ */

struct packet
{
    int start; // Hash function of the data created by hash_fn
    string s;
};

#endif
