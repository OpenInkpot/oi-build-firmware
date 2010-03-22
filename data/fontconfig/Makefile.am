FC_CACHE_FILES=$(wildcard *.cache-*)

fc_cache_dir=$(datadir)/oi-build-firmware/fontconfig

install-data-hook:
	for cf in $(FC_CACHE_FILES); do \
		$(mkdir_p) $(DESTDIR)$(fc_cache_dir); \
		$(INSTALL_DATA) $$cf $(DESTDIR)$(fc_cache_dir); \
	done
