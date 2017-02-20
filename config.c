#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <popt.h>       /* popt library for parsing config files and command line options */

#include "config.h"

#include "logging.h"
#include "common.h"

/* static data */

static tConfigOptions  configOptions = {
    kLogNotice,
    NULL,
    NULL,
    0,
    NULL
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

/* popt grammar for parsing command line options */
static struct poptOption optionsVocab[] =
{
    /* longName, shortName, argInfo, arg, val, autohelp, autohelp arg */
    { "config",  'c', POPT_ARG_STRING, &configOptions.configFile, 1, "read Configuration from <file>",              "path to file" },
    { "logfile", 'l', POPT_ARG_STRING, &configOptions.logFile,    0, "send logging to <file>",                      "path to file" },
    { "debug",   'd', POPT_ARG_INT,    &configOptions.debugLevel, 0, "set the amount of logging (syslog priority)", "debug level"  },
    POPT_AUTOHELP
    POPT_TABLEEND
};

#pragma GCC diagnostic pop

int fileIsReadable( const char * file, int errIfMissing )
{
    int notReadable;

    notReadable = (access(file, R_OK) != 0);

    if ( notReadable )
    { /* don't have access - figure out why */
        switch (errno)
        {
        case ENOENT: /* nothing there - may not be an error */
            if (errIfMissing)
            {
                logError( "Cannot find config file \"%s\"", file );
            }
            break;

        default:
            logError( "Cannot read config file \"%s\" (%s [%d])", file, strerror(errno), errno );
            break;
        }
    }

    return !notReadable;
}

#define ARGV_SIZE   200

int parseConfigFile( poptContext context, const char * configFile )
{
    int             result;
    int             len;
    FILE           *confFD;
    char           *first, *key, *value, *saved;
    char            line[1024];
    int             argc;
    char          **argv;

    result = 0;

    argc = 0;
    argv = calloc( ARGV_SIZE, sizeof( char * ) );

    if ( fileIsReadable( configFile, 1 ) )
    {
        confFD = fopen( configFile, "r" );
        if (confFD == NULL)
        {
            logError( "unable to open config file \"%s\" (%d: %s)", configFile, errno, strerror( errno ));
            result = errno;
        }
        else
        {
            while ( fgets( line, sizeof( line ), confFD ) != NULL && !feof( confFD ) )
            {
                /* skip forward to the first non-whitespace character */
                first = strtok_r( line, " \t\n\r", &saved );
                switch ( *first )
                {
                case '\0': /* blank line (only whitespace) */
                case '#':  /* comment line */
                    break;

                default:
                    /* split each line */
                    key   = strtok_r( NULL, "= \t\n\r", &saved );
                    value = strtok_r( NULL, "= \t\n\r", &saved );

#if 0
                    logDebug( "key: \"%s\", value: \"%s\"",
                               key   != NULL ? key   : "(null)",
                               value != NULL ? value : "(null)" );
#endif

                    /* add to argv */
                    if ( key != NULL )
                    {
                        len = strlen( key + 2 + 1 );
                        argv[argc] = malloc( len );
                        if (argv[argc] != NULL)
                        {
                            snprintf( argv[argc], len, "--%s", key );
                            ++argc;
                        }
                    }
                    if ( value != NULL )
                    {
                        argv[argc] = strdup( value );
                        if (argv[argc] != NULL)
                            { ++argc; }
                    }
                    break;
                }
                argv[argc] = NULL;
            }
            result = ferror( confFD );

            if (result == 0)
            {
                result = poptStuffArgs( context, (const char **)argv );
            }
        }
    }

    return result;
}

static int seenConfigFile = 0;

tConfigOptions * parseConfiguration( int argc, const char *argv[] )
{
    int result;
    poptContext context;
    const char *path;
    const char **argvCopy;
    int i;

    context = poptInit( argc, argv, optionsVocab, NULL );

    if ( context == NULL )
    {
        logError( "failed to get a context to parse the command line" );
    }
    else
    {
        while ( (result = poptGetNextOpt( context )) >= 0 )
        {
            switch (result)
            {
            case 1:
                if (!seenConfigFile)
                {
                    path = poptGetOptArg( context );
                    /* attempt to parse the config file */
                    parseConfigFile( context, path );
                    /* start over, command line options always take precedence */
                    poptResetContext( context );
                    /* remember that we did this already, resetting
                     * the context means we'll be called again */
                    seenConfigFile = 1;
                }
                break;

            default:
                break;
            }
        }

        if (result < -1)
        {
            logError( "problem with a command line option \"%s\" (%s)",
                       poptBadOption( context, POPT_BADOPTION_NOALIAS ),
                       poptStrerror( result ) );
        }
        else
        {
            argv = poptGetArgs( context );

            argc = 0;
            if (argv != NULL) {
                while (argv[argc] != NULL) { ++argc; }

                if (argc > 0) {
                    argvCopy = calloc(argc + 1, sizeof(char *));

                    if (argvCopy != NULL) {
                        for (i = 0; i < argc; ++i) {
                            argvCopy[i] = strdup(argv[i]);
                        }
                        argvCopy[i] = NULL;

                        configOptions.argc = argc;
                        configOptions.argv = argvCopy;
                    }
                }
            }
        }

        poptFreeContext( context );
    }

    return &configOptions;
}
