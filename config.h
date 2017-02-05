
#ifndef config_h
#define config_h

typedef struct {
    int             debugLevel;     /* controls the amount of logging (syslog priority) */
    char           *configFile;     /* config file path, or NULL for default search */
    char           *logFile;        /* file destination for logs, or NULL if the user didn't supply one */
    int             argc;           /* count of the command line parameters that weren't consumed by popt */
    const char    **argv;           /* the command line parameters that weren't consumed by popt */

} tConfigOptions;

tConfigOptions * parseConfiguration(int argc, const char *argv[] );

#endif
