# HProf file parser

[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/google/hprof-parser/parser)

This is a Go library for parsing Java Virtual Machine heap dump files (.hprof).

Not an official Google product (i.e. a 20% project).

## About this library

Modern Java applications use lots of memory. The size of the heap dumps became
so big that the existing analyzers such as
[jhat](https://docs.oracle.com/javase/7/docs/technotes/tools/share/jhat.html) or
[Eclipse Memory Analyzer](https://www.eclipse.org/mat/) cannot handle them
because of OutOrMemoryError.

This library provides a parser for the JVM heap dump files. You can write your
own heap dump analyzer that fits your needs. Since this is just a parser, it
doesn't have to hold the entire dump on memory. You can just extract necessary
data for analysis.

This is written by a single person in a day, and it can parse only enough to
handle heap dump files that the author had. It doesn't support all record types
that hprof files can have. Send us a patch if need those unimplemented parts.

## About HProf files

The library was written based on OpenJDK's
[heapDumper.cpp](http://hg.openjdk.java.net/jdk/jdk/file/4b49cfba69fe/src/hotspot/share/services/heapDumper.cpp).
The data structure is a straight-forward dump of JVM's internal structure. See
the comments in `hprofdata/hprofdata.proto`.
