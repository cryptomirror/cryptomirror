#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
    these are wrappers for memory allocation so that
    security features can later be added
*/

typedef struct mem_header
{
    unsigned long size;
    unsigned long flags;
} mem_header;

void*
allocate_mem(unsigned long size, unsigned long flag)
{
    struct mem_header *x;
    
    if (size > (1<<30LL))
    {
        return NULL;
    }
    
    //
    // XXX make this an mmap of non pageable memory instead.
    //
    x = calloc(2, size +  sizeof(*x));
    if (x == NULL)
    {
        return NULL;
    }
    x->size = size;
    x->flags = 0;
    return x+1;
}

void
release_mem(void *ptr)
{
    struct mem_header *x;
    x = ptr;
    x = x - 1;
    //
    // Clear memory on free
    //
    memset(ptr, 0, x->size);
    free(x);
}

//#define TST 1
#ifdef TSTMEM
#include <stdio.h>
int main()
{
    char *x = allocate_mem(40, 0);
    strcpy(x, "hi there\n");
    printf("%s", x);
    release_mem(x);
}
#endif
