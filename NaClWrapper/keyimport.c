#include "common.h"

enum trust_state
{
    /* havent set a trust level yet for this one*/
    Unknown,
    /* not trusted */
    Untrusted,
    /* trusted but not verified */
    LazyTrusted,
    /* trusted and verified */
    VerifiedTrusted
}; 

typedef struct Identity
{
    unsigned char *name;
    unsigned char *pk;
    unsigned long state;
    void *data;
} Identity;

Identity*
make_identity(unsigned char *name, unsigned char *pk)
{
    Identity *ident;
    ident = allocate_mem(sizeof(*ident), 0);
    if (ident != NULL)
    {
        ident->name = name;
        ident->pk = pk;
    }
    ident->state = Unknown;
    ident->data = NULL;
    return ident;
}

int
set_trust_level(Identity *ident, unsigned int trust_state)
{
    ident->state = trust_state;
    return 0;
}

int
import_key(unsigned char *name, unsigned char *pk)
{
    Identity *ident;
    ident = make_identity(name, pk);
    
    //
    // XXX add to key store
    //
    return 0;
}

#ifdef TSTIMPORT
#include <stdio.h>
int main(int argc, char *argv[])
{
    unsigned char *name, *pk;
    Identity *ident;
    name = (unsigned char *)"name,";
    pk = (unsigned char *) "fake pk";
    ident = make_identity(name, pk);
    release_mem(ident);
    return 0;
}
#endif

