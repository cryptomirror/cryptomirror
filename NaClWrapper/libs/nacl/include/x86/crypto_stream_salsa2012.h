#ifndef crypto_stream_salsa2012_H
#define crypto_stream_salsa2012_H

#define crypto_stream_salsa2012_x86_xmm5_KEYBYTES 32
#define crypto_stream_salsa2012_x86_xmm5_NONCEBYTES 8
#ifdef __cplusplus
#include <string>
extern std::string crypto_stream_salsa2012_x86_xmm5(size_t,const std::string &,const std::string &);
extern std::string crypto_stream_salsa2012_x86_xmm5_xor(const std::string &,const std::string &,const std::string &);
extern "C" {
#endif
extern int crypto_stream_salsa2012_x86_xmm5(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa2012_x86_xmm5_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa2012_x86_xmm5_beforenm(unsigned char *,const unsigned char *);
extern int crypto_stream_salsa2012_x86_xmm5_afternm(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa2012_x86_xmm5_xor_afternm(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_stream_salsa2012 crypto_stream_salsa2012_x86_xmm5
#define crypto_stream_salsa2012_xor crypto_stream_salsa2012_x86_xmm5_xor
#define crypto_stream_salsa2012_beforenm crypto_stream_salsa2012_x86_xmm5_beforenm
#define crypto_stream_salsa2012_afternm crypto_stream_salsa2012_x86_xmm5_afternm
#define crypto_stream_salsa2012_xor_afternm crypto_stream_salsa2012_x86_xmm5_xor_afternm
#define crypto_stream_salsa2012_KEYBYTES crypto_stream_salsa2012_x86_xmm5_KEYBYTES
#define crypto_stream_salsa2012_NONCEBYTES crypto_stream_salsa2012_x86_xmm5_NONCEBYTES
#define crypto_stream_salsa2012_BEFORENMBYTES crypto_stream_salsa2012_x86_xmm5_BEFORENMBYTES
#define crypto_stream_salsa2012_IMPLEMENTATION "crypto_stream/salsa2012/x86_xmm5"
#ifndef crypto_stream_salsa2012_x86_xmm5_VERSION
#define crypto_stream_salsa2012_x86_xmm5_VERSION "-"
#endif
#define crypto_stream_salsa2012_VERSION crypto_stream_salsa2012_x86_xmm5_VERSION

#endif
