CC      = gcc
CFLAGS  += -Wall -Wextra
LDFLAGS += -ldl -lpopt -lcalg

TARGETS = generatemacdb maclookup
TGTOBJ  = $(patsubst %, obj/%.o, $(TARGETS))
SRC     = $(wildcard *.c)
OBJ     = $(patsubst %.c, obj/%.o, $(SRC))

debug:   $(TARGETS)
    CFLAGS += -g
#   CFLAGS += -finstrument-functions
    LDFLAGS += -Wl,--export-dynamic

release: $(TARGETS)
    CFLAGS += -Werror
    LDFLAGS += -Wl,--strip-all

obj/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -DLOG_SCOPE=$(*F) -D_LINE_COUNT=`wc -l $< | cut -d ' ' -f 1`

$(TARGETS):  $(OBJ)
	$(CC) -o $@ obj/$@.o $(filter-out $(TGTOBJ), $^) $(LDFLAGS)

obj/logscopes.inc:
	@echo "recreating" $@
	@mkdir -p $(@D)
	@echo "/*** automatically generated - do not edit ***/" > $@
	@echo "typedef enum {" > $@
	@echo $(foreach scope, $(wildcard *.c), kLog_$(basename $(scope)),) >> $@
	@echo "kMaxLogScope } eLogScope;" >> $@
	@echo "" >> $@
	@echo $(foreach scope, $(wildcard *.c), "extern unsigned int gLogMax_$(basename $(scope));" ) >> $@

obj/logscopedefs.inc:
	@echo "recreating" $@
	@mkdir -p $(@D)
	@echo "/*** automatically generated - do not edit ***/" > $@
	@echo "void logLogInit( void ) {" >> $@
	@echo $(foreach scope, $(wildcard *.c), "gLog[kLog_$(basename $(scope))].name = \"$(basename $(scope))\";" ) >> $@
	@echo "}" >> $@


logging.h: obj/logscopes.inc

logging.c: obj/logscopedefs.inc

*.c: logging.h

clean:
	rm -f $(TARGETS) obj/*

.PHONY: debug release clean
