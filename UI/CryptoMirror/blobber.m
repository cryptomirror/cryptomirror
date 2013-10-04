#include "blobber.h"
#include "b64.h"

//
// Make a blob from raw bytes and a size
//
char *
make_blob_string(const unsigned char *bytes, unsigned int size)
{
    char *ret;
    char *b64;
    size_t alloc_size;
    ret = NULL;
    b64 = NULL;

    if (size > BLOB_SIZE_LIMIT) goto End;
    
    b64 = calloc(B64ENCLEN(size), 1);
    if (b64 == NULL) goto End;
    
    b64_ntop(bytes, size, b64, B64ENCLEN(size));
    
    alloc_size = B64ENCLEN(size) + strlen(CRYPTO_MIRROR_HEADER) + strlen(CRYPTO_MIRROR_TRAILER) + 1;

    if (alloc_size > BLOB_SIZE_LIMIT) goto End;

    ret = calloc(alloc_size, 1);
    if (ret == NULL) goto End;

    strlcat(ret, CRYPTO_MIRROR_HEADER, alloc_size);
    strlcat(ret, b64, alloc_size);
    strlcat(ret, CRYPTO_MIRROR_TRAILER, alloc_size);
    
End:
    if (b64)
        free(b64);
    
    return ret;
}


int
decode_blob_string(char *bytes, unsigned char **output, unsigned int *size)
{
    int ret;
    char keep;
    char *tail;
    unsigned char *buf;
    size_t sz;
    
    ret = -1;
    buf = NULL;
    
    tail = strlen(bytes) + bytes - strlen(CRYPTO_MIRROR_TRAILER);
    
    if (bytes != strstr(bytes, CRYPTO_MIRROR_HEADER)) goto End;
    if (tail != strstr(tail, CRYPTO_MIRROR_TRAILER))
    {
        printf("Mis match: %s", tail);
        goto End;
    }
    keep = *tail;
    *tail = 0x00;
    
    bytes += strlen(CRYPTO_MIRROR_HEADER);

    sz = B64DECLEN(strlen(bytes));
    if (sz > BLOB_SIZE_LIMIT) goto End;
    
    buf = malloc(sz);
    if (buf == NULL) goto End;
    
    sz = b64_pton(bytes, buf, sz);
    if (sz == -1)
    {
        goto End;
    }
    *tail = keep;

    *output = buf;
    buf = NULL;
    
    *size = (unsigned int) sz;

    ret = 0;
End:
    if (buf) free(buf);
    return ret;
}

struct blobs*
extract_blobs (NSString *str)
{
    const char *cstr, *end;
    char *head;
    char *tail;
    char *blob;
    struct blobs *result;
    size_t blob_size;

    result = NULL;
    
    cstr = [str cStringUsingEncoding:NSMacOSRomanStringEncoding];
    if (cstr == NULL)
    {
        goto End;
    }
    end = cstr + strlen(cstr);
    
    while (cstr < end)
    {
        head = strstr(cstr, CRYPTO_MIRROR_HEADER);
        if (head == NULL) goto End;;
        tail = strstr(cstr, CRYPTO_MIRROR_TRAILER);
        if (tail == NULL)   goto End;
        if (tail < head) goto End;
        if (tail - head < 1) goto End;
        if (tail - head > BLOB_SIZE_LIMIT) goto End;
        
        if (!result) {
            result = malloc(sizeof(struct blobs));
            if (result == NULL) goto End;
            result->count = 0;
        }
        blob_size = tail + strlen(CRYPTO_MIRROR_TRAILER) - head + 1;
        blob = malloc(blob_size);
        if (!blob) goto End;
        memcpy(blob, head, blob_size);
        blob[blob_size - 1] = '\0';
        
        result->blob[result->count] = blob;
        result->count++;
        if (result->count == BLOB_LIMIT) goto End;

        cstr = tail + strlen(CRYPTO_MIRROR_TRAILER);
    }
    
End:
    return result;
}

void
release_blobs (struct blobs* blobs)
{
    unsigned int i;
    if (!blobs) return;
    
    for(i = 0; i < blobs->count; i++)
        free(blobs->blob[i]);
    free(blobs);
}

/*
 char *b;
 unsigned char *dest;
 unsigned int size;
 int ret;
 
 b = make_blob_string("Hello World\n", 20);
 ret = decode_blob_string(b, &dest, &size);
 */
