/*
 */

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

typedef char                tBucket[4];
typedef unsigned short      tBucketIndex;   /* an index into the gBuckets array */
typedef unsigned short      tCompanyIndex;
typedef unsigned long long  tMACaddr;       /* must be at least 48 bits wide */

extern const char      *gExecName;          /* base name of this executable, derived from argv[0] */

extern tBucket         *gBuckets;
extern tCompanyIndex   *gMACtoCompany;
extern tBucketIndex    *gCompanies;
extern unsigned char   *gCompaniesLen;

extern char             toHex[];

tMACaddr    parseMAC( const char *text, int len );
char *      MACtoString( tMACaddr macAddr );
char *      assembleCompany( tCompanyIndex company );

void        mapDatabase(void);
void        unmapDatabase(void);
