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

extern const char * gExecName;      /* base name of the execuatable, derived from argv[0]. Same for all processes */
extern const char * gProcessName;   /* Name of this process - set differently in each process */
