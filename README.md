# Malloc
### Implementation by [Jaden Holladay](http://jadenholladay.com)
### About
To design and implement a memory allocator in C.
This implementation makes use of an explicit free list. The rules for allocation are to find the first available block that fits the amount to be allocated. This first fit strategy can be modified easily by changing the logic contained within find_available_block.
### Files
**********************************
mm.{c,h}
	Contains the implementation of malloc.

mdriver.c
	The malloc driver that tests your mm.c file

short{1,2}-bal.rep
	Two tiny tracefiles to help you get started.

Makefile
	Builds the driver

### Other support files for the driver
**********************************

config.h	Configures the malloc lab driver
fsecs.{c,h}	Wrapper function for the different timer packages
clock.{c,h}	Routines for accessing the Pentium and Alpha cycle counters
fcyc.{c,h}	Timer functions based on cycle counters
ftimer.{c,h}	Timer functions based on interval timers and gettimeofday()
memlib.{c,h}	Wraps mmap with tracking
pagemap.{c,h}	Used by "memlib.c" to check page operations


### Building and running the driver
*******************************
To build the driver, type "make" to the shell.

To run the driver on a tiny test trace:

	unix> mdriver -V -f short1-bal.rep

The -V option prints out helpful tracing and summary information.

To get a list of the driver flags:

	unix> mdriver -h
