
# Common flags and variables
DEVDIR=wslib
WORKDIR=$(DEVDIR)
BUILDIR=$(WORKDIR)/build
LIBDIR=$(BUILDIR)/lib
GENLIB=genCppTools
FULLGENLIB=lib$(GENLIB).a
LIBDIRGENLIB=$(LIBDIR)/$(FULLGENLIB)
CXXFLAGS=-g -Wall  # Consider renaming to CFLAGS for consistency
.DEFAULT_GOAL := all
.PHONY: all clean
