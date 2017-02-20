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


/*
 * Main entry point.
 * parse command line options and launch background process.
 *
 */
int main( int argc, const char *argv[] )
{
    tConfigOptions *config;

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

    //logDebug( "%s started", gExecName );

    mapDatabase();

    /* do something useful */
    for ( int i = 0; i < config->argc; ++i )
    {
        tMACaddr macAddr = parseMAC( config->argv[i], strlen( config->argv[i] ) );

        char *macAsString = MACtoString( macAddr );
        char *companyName = assembleCompany( gMACtoCompany[(macAddr >> 24) & 0x00FFFFFF] );

        fprintf( stdout, "%s is assigned to %s\n", macAsString, companyName );

        free( macAsString );
        free( companyName );
    }

    unmapDatabase();

    stopLogging();

    return 0;
}
