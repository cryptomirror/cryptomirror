#ifndef _BSD_BASE64_H
#define _BSD_BASE64_H

#ifndef HAVE___B64_NTOP
# ifndef HAVE_B64_NTOP
size_t b64_ntop(u_char const *src, size_t srclength, char *target,
    size_t targsize);
size_t b64_pton(char const *src, u_char *target, size_t targsize);
# endif /* !HAVE_B64_NTOP */
# define __b64_ntop b64_ntop
# define __b64_pton b64_pton
#endif /* HAVE___B64_NTOP */

// Last +1 below to accommodate trailing '\0':
#define B64ENCLEN(len) (((len + 2)/3)*4 + 1)
// technically *3 / 4 but meh
#define B64DECLEN(len) (len)


#endif /* _BSD_BINRESVPORT_H */

