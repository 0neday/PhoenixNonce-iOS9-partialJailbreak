#ifndef libjb_h_included
#define libjb_h_included


struct trust_dsk {
    unsigned int version;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct hash_entry_t {
    uint16_t num;
    uint16_t start;
} __attribute__((packed));

typedef uint8_t hash_t[20];

extern hash_t *allhash;
extern unsigned numhash;
extern struct hash_entry_t *amfitab;
extern hash_t *allkern;

/* can be called multiple times. kernel read func & amfi/top trust chain block are optional */
int grab_hashes(const char *root, size_t (*kread)(uint64_t, void *, size_t), uint64_t amfi, uint64_t top);
int misvalid(const char *fpath);
void untar(FILE *a, const char *path);

#endif
