# OS_Project_4
Repo for project 4

Our strategy was to break up the code into the reading the input, producer and consumer and the hash with hash table. We read in a packet of data and then check the size of the packet. We then discard the size and are just left with the data. We then put the data into a hash and store the hash into a hash table based on the int value of the data. Then we continue to do this process throughout the length of the file and compare hash values to see if there is a hit. Then we can compute the redundancy. For level 2, we will use the window size and go through each packet. If there is a match, we will go to the next bit to see if there is a match until there is not and then have a pointer to the end and start the next 64 byte window at that end point. 

We believe that for our program needs XX threads to be optimal 
Put in time command and output 
Kaitlyn worked on the reading the data from the pcap files and compiling all of the functionality together into the executable 
Alanna worked on the producer and consumer code and making sure there was multithreading 
Chris worked on developing a way to hash the data and creating a table to store the packet structs into 

For threading we did producer and consumer. We decided to have one consumer thread that would read in and take the packet data that we would need and the rest of the threads would be consumer threads. Each consumer thread would get a packet of data and then would can match to see if there is a ‘hit’ in the hash table. This way you are able to have multiple packets being hashed and stored at once. If they have the same hash value then you can compare the actual values and see if it is a match. 
We decided to do a random evict so we take a random integer and remove that hash from the table. This was a quick way to remove that saved time and kept the efficiency up. 

Performance: 


