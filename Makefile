# BasicAuthBF Makefile
# --------------------
# By @dan1t0 - jdanimartinez[AT]gmail.com

CC = gcc
PACKAGE = basicauthbf
VERSION = 0.4
OPTS = -lpthread
DBG = -ggdb


all:
	$(CC) BasicAuthBF.c -o $(PACKAGE)_$(VERSION) $(OPTS)

debug:
	$(CC) $(OPTS) $(PACKAGE).c $(DBG) -o $(PACKAGE)_$(VERSION)_DBG

clean:
	rm -f $(PACKAGE)_$(VERSION)
	rm -f $(PACKAGE)_$(VERSION)_DBG
	rm -rf $(PACKAGE)_$(VERSION)_DBG.dSYM
