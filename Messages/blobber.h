#ifndef _BLOBBER_H
#define _BLOBBER_H
#define CRYPTO_MIRROR_HEADER "+CRYPTOMIRROR"
#define CRYPTO_MIRROR_TRAILER "RORRIMOTPYRC+"
#define BLOB_LIMIT 32
#define BLOB_SIZE_LIMIT 1024*1024
struct blobs
{
    unsigned int count;
    char *blob[BLOB_LIMIT];
};

//
// Scans for CRYPTO MIRROR blobs in an NSString and return a blobs struct
// if it finds any occurances (with up to 32 blob entries)
//
struct blobs *
extract_blobs (NSString *str);

//
// Make a blob string from raw bytes and a size
//
char *
make_blob_string(const unsigned char *bytes, unsigned int size);

//
// Return raw bytes from a blob
//
int
decode_blob_string(char *bytes, unsigned char **output, unsigned int *size);

//
// Free a blobs structure allocation and its entries
//
void
release_blobs (struct blobs * blobs);
#endif