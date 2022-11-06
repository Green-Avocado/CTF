#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(DEBUG)
#define DEBUG 0
#endif

#define debug_printf(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)


#define MAXENTRYSIZE 64


char *stringArea;

char input_buffer[MAXENTRYSIZE];

typedef struct entry{
    // next entry node
    struct entry *next;
    //size of the string pointed to 
    u_int32_t entry_size;
    //entry string in the string storage buffer
    char *entry_string;

} entry;

struct entry *entry_list_head;

//helper function to make a new entry
entry * create_entry(char * entry_string, char * string_location, int string_len){
    entry *new_entry = malloc(sizeof(entry));
    if(!new_entry){
        exit(-1);
    }
    new_entry->entry_string = string_location;
    new_entry->entry_size = string_len;
    strncpy(new_entry->entry_string, entry_string, string_len);
    new_entry->next = NULL;
    return new_entry;
}

//DEBUG 
//print hex of buffer
// https://gist.github.com/ccbrown/9722406   ------  licensed WTFPL
void dumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		debug_printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			debug_printf(" ");
			if ((i+1) % 16 == 0) {
				debug_printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					debug_printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					debug_printf("   ");
				}
				debug_printf("|  %s \n", ascii);
			}
		}
	}
}


//DEBUG
void print_all_elements(){
    debug_printf("printing list\n");
    struct entry *current = entry_list_head;
    if(current == NULL){
        debug_printf("empty list\n");
        return;
    }
    for (; current != NULL; current=current->next){
        debug_printf("element{ len: %d\n",current->entry_size);
        #if DEBUG
        fwrite(current->entry_string, sizeof(char), current->entry_size, stdout);
        #endif
        debug_printf("}\n");
    }
}

// loop through all the entries and print if there are any matches
//DEVELOLPER NOTE: this seems broken.....
int search_entries(char *string){
    entry *current = entry_list_head;
    int in_len = strlen(string) -1;
    while (current != NULL)
    {
        //check that the srtings are the same length
        int entry_len = current->entry_size + 1; 
        if(in_len == entry_len){
            debug_printf("matching len (%d,%d)   \n",in_len,entry_len);
            if (strncmp(string, current->entry_string, entry_len) == 0)
            {
                printf("found match\n");
                return 1;
            }
        }
        //move along
        current = current->next;
    }
    printf("no match found\n");
    return 0;
}
//add a string entry, places it in the next large enough slot in our string buffer
int add_entry(char *entryString)
{
    debug_printf("adding %s \n", entryString);
    int string_space_needed = strlen(entryString) - 1;
    // if the list is empty, just make a new entry at the beginning
    if(entry_list_head == NULL){
        entry_list_head = create_entry(entryString, stringArea, string_space_needed);
    }
    //otherwise go through the items
    //if the item is the first, check if there is a gap big enough infront 
    //then check if there is a gap in between
    else{
        
        struct entry *current = entry_list_head;

        char *last_string_start = current->entry_string;
        char *last_string_end = last_string_start + current->entry_size;

        
        while(current->next !=NULL){
            debug_printf("element\n");
            current = current->next;
            last_string_start = current->entry_string;
            last_string_end = last_string_start + current->entry_size;
        }
        //if we are at end of list, just make a new entry at the end
        current->next = create_entry(entryString, last_string_end, string_space_needed);
    }
}

//remove an entry that matches the string
int remove_entry(char *string){
    entry *current = entry_list_head;
    entry *previous = current;
    while(current != NULL){
        int string_len = strlen(string) - 1;
        //first check if strings are same length
        if(string_len == current->entry_size){
            //DEBUG
            debug_printf("same len \n");
            if (strncmp(string, current->entry_string, current->entry_size) ==0)
            {
                printf("found match\n");
                previous->next = current->next;
                if(current == entry_list_head){
                    entry_list_head = current->next;
                }
                free(current);
                return 1;
            }
        }
        //move along
        previous = current;
        current = current->next;
    }
    printf("no match found\n");
}

void process_user_input(){
    //zero out our input buffer
    memset(input_buffer, 0x0, MAXENTRYSIZE);
    //ask the user to pick an action
    printf("Type your command\n\tadd, remove, or search :\n");
    //get the action
    fgets(input_buffer, MAXENTRYSIZE, stdin);
    //DEBUG
    //printf("%s", input_buffer);
    if (!strncmp(input_buffer, "add\n",MAXENTRYSIZE))
    {
        printf("what entry would you like to add?\n");
        //zero out our input buffer
        memset(input_buffer, 0x0, MAXENTRYSIZE);
        //fgets returns null on eof,

        if (fgets(input_buffer, MAXENTRYSIZE, stdin)){
            if (strnlen(input_buffer, MAXENTRYSIZE) > 1){
                printf("inserting: %s", input_buffer);
                add_entry(input_buffer);
            }
            else
            {
                printf("entry too short\n");
            }
        }
    }
    if (!strncmp(input_buffer, "remove\n",MAXENTRYSIZE))
    {
        printf("what entry would you like to remove?\n");
        //zero out our input buffer
        memset(input_buffer, 0x0, MAXENTRYSIZE);
        //fgets returns null on eof,

        if (fgets(input_buffer, MAXENTRYSIZE, stdin)){
            if (strnlen(input_buffer, MAXENTRYSIZE) > 1){
                printf("removing: %s", input_buffer);
                remove_entry(input_buffer);
            }
            else
            {
                printf("entry too short\n");
            }
        }
    }
    if (!strncmp(input_buffer, "search\n",MAXENTRYSIZE))
    {
        printf("what entry would you like to search for?\n");
        //zero out our input buffer
        memset(input_buffer, 0x0, MAXENTRYSIZE);
        //fgets returns null on eof,

        if (fgets(input_buffer, MAXENTRYSIZE, stdin)){
            if (strnlen(input_buffer, MAXENTRYSIZE) > 1){
                printf("searching: %s", input_buffer);
                search_entries(input_buffer);
            }
            else
            {
                printf("entry too short\n");
            }
        }
    }
    dumpHex(stringArea, MAXENTRYSIZE * 16);
    print_all_elements();
}


// main program body
int main() {
    stringArea = malloc(MAXENTRYSIZE * 16);
    
    add_entry("Test entry one\n");
    add_entry("Test entry two\n");
    add_entry("Test entry three\n");
    add_entry("Yet another test entry here!\n");

#ifdef PREPPUZZLE
    // add_entry("TEST\n");
    add_entry(CTFKEY);
    remove_entry(CTFKEY);

#endif
    
    while(1){
        process_user_input();
    }

    return 0;
}