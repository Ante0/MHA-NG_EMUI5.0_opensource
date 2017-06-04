AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = -Wall 
sbin_PROGRAMS = sload.f2fs
sload_f2fs_SOURCES = main.c sload.c checkpoint.c index.c file.c dir.c node.c segment.c xattr.c bit_operations.c f2fs.h sload.h $(top_srcdir)/include/f2fs_fs.h
sload_f2fs_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la

