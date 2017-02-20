/*
*/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>    /* C99 boolean types */
#include <signal.h>     /* signal handling */
#include <errno.h>      /* provides global variable errno */
#include <string.h>     /* basic string functions */
#include <ctype.h>

#include <libcalg-1.0/libcalg/trie.h>	/* C Algorithms -  http://fragglet.github.io/c-algorithms/ */
#include <fcntl.h>

#include "common.h"     /* common stuff */
#include "config.h"     /* config file & command line configuration parsing */

#include "logging.h"    /* my logging support */


/*
 * global variables
 */


const char *  gExecName;  /* base name of the executable, derived from argv[0]. Same for all processes */


/* seed the bucket trie with common words that have the right Capitalization */
const char *seedBucketTrie = "Inc Corp Corporation Co Ltd GmbH LLC Technology Electronics Solutions";

/*
 * buckets are aligned on four-byte boundaries. This allows us to address 256k of strings
 * while still indexing it with an unsigned short.
 *
 * A string fragment almost always spans more than one bucket. An index into gBuckets[]
 * can be cast to a (char *), since the fragment is zero padded out to the next
 * bucket boundary
 */

Trie                   *gBucketTrie;            /* trie for storing pointers to the text fragments */
unsigned long           gFragCount = 0;         /* total number of strings in gBuckets[] */
unsigned long           gNextFreeBucket = 1;    /* next free bucket in gBuckets[] */

/*
 * A company name is represented by an index into gCompanies[] and gCompaniesLen[],
 * The index is the starting point in gCompanies[] of a list of indexes into gBuckets[].
 * gCompaniesLen[] indicates the length of that list.
 * See assembleCompany() for the method to reassemble the company name.
 */

Trie                   *gCompanyTrie;            /* trie for storing pointers to the company tuples */
unsigned long           gCompanyCount = 0;
tCompanyIndex           gNextFreeCompany = 1;

tMACaddr gMACBitsInUse = 0;


/* Master's SIGCHLD handler.
 *
 * When a process is fork()ed by a process, the new process is an exact copy
 * of the old process, except for a few values, one of which is that the parent
 * pid of the child is that of the process that forked it.
 *
 * When this child exits, the signal SIGCHLD is sent to the parent process to
 * alert it. By default, the signal is ignored, but we can take this opportunity
 * to restart any children that have died.
 *
 * There are many ways to determine which children have died, but the most
 * portable method is to use the wait() family of system calls.
 *
 * A dead child process releases its memory, but sticks around so that any
 * interested parties can determine how they died (exit status). Calling wait()
 * in the master collects the status of the first available dead process, and
 * removes it from the process table.
 *
 * If wait() is never called by the parent, the dead child sticks around as a
 * "zombie" process, marked with status `Z' in ps output. If the parent process
 * exits without ever calling wait, the zombie process does not disappear, but
 * is inherited by the root process (its parent pid is set to 1).
 *
 * Because SIGCHLD is an asynchronous signal, it is possible that if many
 * children die simultaneously, the parent may only notice one SIGCHLD when many
 * have been sent. In order to beat this edge case, we can simply loop through
 * all the known children and call waitpid() in non-blocking mode to see if they
 * have died, and spawn a new one in their place.
 */
void restartChildren(int UNUSED(signal))
{
}

/* Master's kill switch
 *
 * It's important to ensure that all children have exited before the master
 * exits so no root zombies are created. The default handler for SIGINT sends
 * SIGINT to all children, but this is not true with SIGTERM.
 */
void terminateChildren(int UNUSED(signal))
{
}

/* suppress an (apparently) spurious warning */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
/*
    static table used by trapSignals for registering signal handlers
 */
static struct {
    int                 signal;    /* What SIGNAL to trap */
    struct sigaction    action;    /* handler, passed to sigaction() */
} sigpairs[] = {
    /* Don't send SIGCHLD when a process has been frozen (e.g. Ctrl-Z) */
    { SIGCHLD, { &restartChildren, {}, SA_NOCLDSTOP } },
    { SIGINT,  { &terminateChildren } },
    { SIGTERM, { &terminateChildren } },
    { 0 } /* end of list */
};
#pragma GCC diagnostic pop

/*
 * When passed true, traps signals and assigns handlers as defined in sigpairs[]
 * When passed false, resets all trapped signals back to their default behavior.
 */
int trapSignals(bool on)
{
    int i;
    struct sigaction dfl;       /* the handler object */

    dfl.sa_handler = SIG_DFL;   /* for resetting to default behavior */

    /* Loop through all registered signals and either set to
     * the new handler or reset them back to the default */
    i = 0;
    while (sigpairs[i].signal != 0)
    {
        /* notice that the second parameter takes the address of the handler */
        if ( sigaction(sigpairs[i].signal, (on ? &sigpairs[i].action : &dfl), NULL) < 0 )
        {
            return false;
        }
        ++i;
    }

    return true;
}

/* trim the whitespace from the end of the line */
char *trimTail( char *p )
{
    int done = 0;

    do {
        switch (*p)
        {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case '\0':
            --p;
            break;

        default:
            ++p;
            done = 1;
            break;
        }
    } while ( !done );

    return p;
}


/* make the key case-insensitive
 * avoids duplicates only differing in case.
 * caller must dispose of key when finished */
char *genkey( char *frag)
{
    char *result = malloc(strlen(frag)+1);
    if (result != NULL)
    {
        char *p = result;
        while ( *frag != '\0' )
            { *p++ = (char)tolower(*frag++); };
        *p = '\0';
    }
    return result;
}

/* chop up the full company name into fragments. Huge storage savings
 * because of the frequency of repetition of these fragments
 */
#define SEPARATORS  " \t,.()[]{}"

tCompanyIndex tokenizeCompany( const char *company )
{
    char       *saved, *frag, *key, *dest;

    tCompanyIndex  companyIndex;
    tCompanyIndex  result = gNextFreeCompany;
    unsigned char  fragCount = 0;

    /* strtok modifies the string, so make a working copy */
    char *copy = strdup(company);
    if ( copy != NULL )
    {
        frag = strtok_r( copy, SEPARATORS, &saved );
        if ( frag != NULL)
        {
            do
            {
                key = genkey(frag);

                tBucketIndex bucketIndex = (tBucketIndex) (uintptr_t) trie_lookup(gBucketTrie, key);

                if ( bucketIndex == (uintptr_t) TRIE_NULL)
                {
                    /* not found = new, so count it */
                    ++gFragCount;

                    /* try to insert it */
                    if ( trie_insert(gBucketTrie, key, (TrieValue) (uintptr_t) gNextFreeBucket) == 0 )
                    { logError("failed to insert bucket key \"%s\"", key); }
                    else
                    {
                        /* fill the bucket(s) :) */
                        bucketIndex = (tBucketIndex)gNextFreeBucket;
                        gNextFreeBucket += (strlen(frag) / sizeof(tBucket)) + 1;

                        dest = (char *) &gBuckets[bucketIndex];
                        strcpy(dest, frag);
                        logDebug("    new: [0x%04x] = \"%s\"", bucketIndex, dest );
                    }
                }
                free(key);

                gCompanies[gNextFreeCompany++] = bucketIndex;
                ++fragCount;

                frag = strtok_r(NULL, SEPARATORS, &saved);

            } while ( frag != NULL);
        }

        companyIndex = (tCompanyIndex) (uintptr_t) trie_lookup_binary( gCompanyTrie,
                                                                       (unsigned char *)&gCompanies[result],
                                                                       fragCount * sizeof(tBucketIndex) );
        if ( companyIndex == (tCompanyIndex)(uintptr_t) TRIE_NULL )
        {
            gCompaniesLen[result] = fragCount;
            /* not present, so insert it */
            if ( trie_insert_binary( gCompanyTrie,
                                     (unsigned char *)&gCompanies[result],
                                     fragCount * sizeof(tBucketIndex),
                                     (TrieValue) (uintptr_t) result ) == 0 )
            { logError( "failed to insert company \"%s\"", company ); }
        }
        else
        {
            /* we have an identical company already in the trie, so discard this and use that instead */
            gNextFreeCompany = result;  /* reset the free pointer back to where it started */
            result = companyIndex;      /* return the existing entry */
        }
    }

    return result;
}

tCompanyIndex parseCompany( char *text, size_t len )
{
    tCompanyIndex   result = 0;
    char           *str;

    /* trim leading and trailing quote, if present */
    if ( text[0] == '\"' )
        { --len; ++text; }
    if ( text[len-1] == '\"' )
        { --len; }

    str = malloc( len + 1 );
    if ( str == NULL )
    {
        logError("malloc failed");
    }
    else
    {
        bool allCaps = true;
        bool allLower = true;

        char    *p = str;
        long     l = len;
        while ( --l >= 0 )
        {
            /* turn two adjacent double-quotes into one */
            if ( (text[0] == '\"') && (text[1] == '\"') )
                { ++text; --l; }
            if (islower(*text)) { allCaps  = false; }
            if (isupper(*text)) { allLower = false; }
            *p++ = *text++;
        }
        *p = '\0'; /* now it's a C string */

        logDebug( "      company: \"%s\"", str );

        /* The IEEE database is messy. Try to make capitalisation consistent,
         * so we don't end up with many duplicates differing only in case */
        if (allCaps || allLower)
        {
            bool followsSep = true;
            p = str;
            while (*p != '\0')
            {
                if ( strchr( SEPARATORS, *p ) != NULL )
                {
                    followsSep = true;
                }
                else if (followsSep)
                {
                    *p = (char)toupper( *p );
                    followsSep = false;
                }
                else
                {
                    *p = (char)tolower( *p );
                }

                ++p;
            }
            logDebug( "   case fixes: \"%s\"", str );
        }

        result = tokenizeCompany( str );

        logDebug( "  reassembled: \"%s\"", assembleCompany( result ) );

        ++gCompanyCount;

        free(str);
    }

    return result;
}

int parseLine( char *line )
{
    struct {
        char         *text;
        unsigned int  len;
    } field[20];

    int     quoted = 0;
    int     count  = 0;

    char   *p = trimTail( line + strlen(line) - 1 );
    *p = '\0';

    p = line;
    field[count].text = p;
    while ( *p != '\0' )
    {
        switch (*p)
        {
        case '\"':
            quoted = !quoted;
            break;

        case ',':
            if (!quoted)
            {
                field[count].len = p - field[count].text;
                ++count;
                field[count].text = p + 1;
            }
            break;

        default:
            break;
        }
        ++p;
    }
    field[count].len = p - field[count].text;
    ++count;

    //logDebug( "%s", line );

    tMACaddr macAddress = parseMAC( field[1].text, field[1].len );
    gMACBitsInUse |= macAddress;

    tCompanyIndex companyIndex = parseCompany( field[2].text, field[2].len );

    uint32_t index = (uint32_t)((macAddress >> 24) & 0x00FFFFFF);

    gMACtoCompany[ index ] = companyIndex;

    return 0;
}

int parseFile( const char *fileName )
{
    int     result;
    char    line[1024];
    FILE   *inputFile;

    inputFile = fopen( fileName, "r" );
    if (inputFile == NULL)
    {
        logError( "unable to open config file \"%s\" (%d: %s)", fileName, errno, strerror(errno) );
        result = errno;
    }
    else
    {
        /* first line is header for field names - discard */
        fgets( line, sizeof( line ), inputFile );
        if ( !feof( inputFile ) )
        {
            while ( fgets(line, sizeof(line), inputFile) != NULL && !feof(inputFile))
            {
                parseLine(line);
            }
        }
        result = ferror( inputFile );
    }

    return result;
}

tBucketIndex quoteBucket( char *line, tBucketIndex bucket )
{
    char  *p = (char *)&gBuckets[bucket];

    tBucketIndex numBuckets = strlen( p )/sizeof(tBucket) + 1;

    *line++ = '\"';
    for ( int i = numBuckets * sizeof(tBucket); i > 0; --i )
    {
        char c;
        switch ( c = *p++ )
        {
        case '\0': *line++ = '\\'; *line++ = '0';  break;
        case '\t': *line++ = '\\'; *line++ = 't';  break;
        case '\n': *line++ = '\\'; *line++ = 'n';  break;
        case '\r': *line++ = '\\'; *line++ = 'r';  break;
        case '\\': *line++ = '\\'; *line++ = '\\'; break;
        case '?':  *line++ = '\\'; *line++ = '?';  break;

        default:
            if ( isprint( c ) )
                { *line++ = c; }
            else
            {
                *line++ = '\\';
                *line++ = 'x';
                *line++ = toHex[ (c >> 4) & 0x0F ];
                *line++ = toHex[ c & 0x0F ];
            }
            break;
        }
    }

    *line++ = '\"';
    *line   = '\0';

    return bucket + numBuckets;
}

void dumpStructures( FILE *outputFile )
{
    char line[1024];
    unsigned int i;

    fprintf(outputFile, "\nunsigned char gCompaniesLen[] = {\n");

    i = 0;
    while ( i < gNextFreeCompany )
    {
        fprintf( stdout, "%u%c", gCompaniesLen[i], i % 64 == 63 ? '\n' : ',' );
        ++i;
    }

    fprintf(outputFile, "};\n\ntBucketIndex gCompanies[] = {\n");

    i = 0;
    while ( i < gNextFreeCompany )
    {
        fprintf( stdout, "%u%c", gCompanies[i], i % 16 == 15 ? '\n' : ',' );
        ++i;
    }

    fprintf(outputFile, "};\n\nconst char* gBuckets = {\n");

    i = 0;
    while ( i < gNextFreeBucket )
    {
        i = quoteBucket( line, i );
        fprintf( stdout, "/* %5u */ %s\n", i, line );
    }
    fprintf(outputFile, "};\n");
}

/*
 * Main entry point.
 * parse command line options and launch background process.
 *
 */
int main( int argc, const char *argv[] )
{
    int    result;
    tConfigOptions *config;
    int    i;

    /* extract the executable name */
    gExecName = strrchr(argv[0], '/');
    if (gExecName == NULL)
        { gExecName = argv[0]; } // no slash, take as-is
    else
        { ++gExecName; }  // skip past the last slash

    initLogging( gExecName );
    logFunctionTraceOff();
    // enable pre-config logging with some sensible defaults
    startLogging( kLogDebug, NULL );

    config = parseConfiguration( argc, argv );

    // re-enable logging with user-supplied configuration
    startLogging( config->debugLevel, config->logFile );

    logInfo("%s started", gExecName);

    mapDatabase();

    gBucketTrie  = trie_new();
    gCompanyTrie = trie_new();
    if ( gBucketTrie == NULL || gCompanyTrie == NULL )
    {
        logCritical("unable to initialize database");
        exit( __COUNTER__ );
    }

    tokenizeCompany( seedBucketTrie );

    /* do something useful */
    if (argc > 0)
    {
        for (i = 0; i < config->argc; ++i)
        {
            result = parseFile( config->argv[i] );
        }
    }
    else
    {
        logCritical("need at least one OUI CSV file to process");
        exit( __COUNTER__ );
    }

    logNotice( "MAC bits in use: %08llx", gMACBitsInUse );

    //dumpStructures( stdout );

    /* dump a bunch of statistics */
    unsigned long companyStorage = (sizeof(tBucketIndex) + sizeof(unsigned char)) * gNextFreeCompany;
    unsigned long bucketStorage  = gNextFreeBucket * sizeof(tBucket);
    logNotice( "Number of Companies:   %lu (%s in short)",
               gCompanyCount,
               gCompanyCount > UINT16_MAX ? "Warning! does not fit" : "still fits");
    logNotice( "Total company storage: %1.2f KBytes (avg %1.2f bytes each)",
               companyStorage/1024.0,
               companyStorage/(float)gCompanyCount );

    logNotice( "Number of Fragments:   %lu", gFragCount );
    logNotice( "Number of Buckets:     %lu (%s in short)",
               gNextFreeBucket,
               gNextFreeBucket > UINT16_MAX ? "Warning! does not fit" : "still fits");
    logNotice( "Total bucket storage:  %1.2f KBytes (avg %1.2f bytes each)",
               bucketStorage/1024.0,
               bucketStorage/(float)gFragCount );

    trie_free( gBucketTrie );
    trie_free( gCompanyTrie );

    unmapDatabase();

    stopLogging();

    return result;
}
