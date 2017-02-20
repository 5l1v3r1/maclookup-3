//
// Created by Paul on 2/12/2017.
//

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>    /* C99 boolean types */
#include <signal.h>     /* signal handling */
#include <errno.h>      /* provides global variable errno */
#include <string.h>     /* basic string functions */
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "logging.h"

/* global pointers to the mmap'd database */

int             gDatabaseFD;

tBucket        *gBuckets;
tCompanyIndex  *gMACtoCompany;
tBucketIndex   *gCompanies;
unsigned char  *gCompaniesLen;


/*
 * segments in the DB file for MMAP
 */
const off_t   MAC_OFST         = 0;
const size_t  MAC_LEN          = (UINT32_MAX >> 7) + 1;

const off_t   BUCKET_OFST      = (UINT32_MAX >> 7) + 1;
const size_t  BUCKET_LEN       = (UINT16_MAX + 1) * sizeof(tBucket);

const off_t   COMPANY_OFST     = (UINT32_MAX >> 7) + 1 + ((UINT16_MAX + 1) * sizeof(tBucket));
const size_t  COMPANY_LEN      = (UINT16_MAX + 1) * sizeof(uint16_t);

const off_t   COMPANY_LEN_OFST = (UINT32_MAX >> 7) + 1 + ((UINT16_MAX + 1) * (sizeof(tBucket) + sizeof(uint16_t)));
const size_t  COMPANY_LEN_LEN  = (UINT16_MAX + 1) * sizeof(uint8_t);

const off_t   DB_EOF           = (UINT32_MAX >> 7) + 1 + (UINT16_MAX + 1)*7;

char toHex[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

tMACaddr parseMAC( const char *text, int len )
{
    tMACaddr     result = 0;
    int             shift  = 48 - 4; /* a MAC address is 6 bytes (48 bits) long */

    while ( len > 0 && shift >= 0 )
    {
        int c = tolower(*text);
        if ( c >= '0' && c <= '9' )
        {
            result |= ((uint64_t)(c - '0') << shift);
            shift -= 4;
        }
        else if ( c >= 'a' && c <= 'f' )
        {
            result |= ((uint64_t)(c - 'a' + 10) << shift);
            shift -= 4;
        }
        else if (c == ':')
        {
            /* ignore, for convenience */
        }
        else break;

        ++text;
        --len;
    }

    return result;
}

char *MACtoString( tMACaddr macAddr )
{
    int len = 6 * 4; /* six bytes, requiring three characters each */
    char *string = malloc( len );

    char *p = string;
    for ( int i = 44; i >= 0; i -= 4 )
    {
        *p++ = toHex[ (macAddr >> i) & 0xF ];
        if ( !(i & 4) )
            *p++ = ':';
    }
    --p;
    *p = '\0';

    return string;
}

/*
 * debugging code to visually check what comes out matches what goes in (semantically)
 */
char * assembleCompany( tCompanyIndex company )
{
    size_t length = 0;
    char *name;
    tCompanyIndex co;

    int count = gCompaniesLen[company];

    /* first, figure out how much space to malloc */
    co = company;
    for ( int i = 0; i < count; ++i )
    {
        length += strlen( (char *)&gBuckets[gCompanies[co]] ) + 1; /* + 1 for trailing space */
        ++co;
    }

    name = malloc( length + 1 );
    if (name != NULL)
    {
        /* reassemble the company string from the fragments in gBucket[] */
        name[0] = '\0';
        co = company;
        for ( int i = 0; i < count; ++i )
        {
            strcat(name, (char *) &gBuckets[gCompanies[co]]);
            strcat(name, " ");
            ++co;
        }
        /* nuke the trailing space */
        name[strlen(name) - 1] = '\0';
    }

    return name;
}

void * mapFileToMemory( int fd, off_t offset, size_t length)
{
    const int prot  = PROT_READ  | PROT_WRITE;
    const int flags = MAP_SHARED | MAP_NORESERVE;

    void *result = mmap( NULL, length, prot, flags, fd, offset );

    //logDebug( "%p = map from %08lx for %08lx bytes", result, offset, length);
    if ( result == (unsigned char *)-1 )
    {
        logError( "unable to map file into memory (%d: %s)", errno, strerror(errno) );
        exit( __LINE__ );
    }
    return result;
}

void mapDatabase(void)
{
    gDatabaseFD = open( "oui.db", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );

    if ( gDatabaseFD == -1 )
    {
        logError( "Unable to open/create OUI DB file (%d: %s)", errno, strerror( errno ));
        exit( __LINE__ );
    }
    else
    {
        int err = posix_fallocate( gDatabaseFD, 0, DB_EOF );
        if ( err != 0 )
        {
            logError( "Unable to allocate space for database file (%d: %s)", err, strerror( err ));
            exit( __LINE__ );
        }
    }

    gMACtoCompany = mapFileToMemory( gDatabaseFD, MAC_OFST, MAC_LEN );
    gBuckets      = mapFileToMemory( gDatabaseFD, BUCKET_OFST, BUCKET_LEN );
    gCompanies    = mapFileToMemory( gDatabaseFD, COMPANY_OFST, COMPANY_LEN );
    gCompaniesLen = mapFileToMemory( gDatabaseFD, COMPANY_LEN_OFST, COMPANY_LEN_LEN );
}


void unmapDatabase(void)
{
    munmap( gMACtoCompany, MAC_LEN );
    munmap( gBuckets,      BUCKET_LEN );
    munmap( gCompanies,    COMPANY_LEN );
    munmap( gCompaniesLen, COMPANY_LEN_LEN );

    close( gDatabaseFD );
}
