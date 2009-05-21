logodir=$(datadir)/esplash-data

install-data-hook:
	for logo in $(wildcard *.png); do \
		$(mkdir_p) $(DESTDIR)$(logodir); \
		$(INSTALL_DATA) $$logo $(DESTDIR)$(logodir); \
	done
