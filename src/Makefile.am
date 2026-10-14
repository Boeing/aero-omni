AM_CFLAGS = -Wall $(DPDK_CFLAGS) $(LIBJSON_CFLAGS)
AUTOMAKE_OPTIONS = subdir-objects

sbin_PROGRAMS = aerod

aerod_SOURCES = \
	main.c main.h \
	aero.c aero.h \
	aero_config_utils.c aero_config_utils.h
	
aerod_LDADD = \
	$(DPDK_LIBS) $(LIBJSON_LIBS) -lcrypto
