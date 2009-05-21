LOGO=$(wildcard *.png)

logodir=$(datadir)/oi-build-firmware

install-data-hook:
	for logo in $(LOGO); do \
		$(mkdir_p) $(DESTDIR)$(logodir); \
		$(INSTALL_DATA) $$logo $(DESTDIR)$(logodir); \
	done
