PKG_CONFIG = pkg-config
PKG_CONFIG_CFLAGS = $(PKG_CONFIG) --cflags
PKG_CONFIG_LIBS = $(PKG_CONFIG) --libs


all:
	@echo "Valid targets: ssh-askpass-gnome ssh-askpass-gtk+2 ssh-askpass2-gtk+3"

ssh-askpass-gnome: gnome-ssh-askpass1.c
	$(CC) $(CFLAGS) `gnome-config --cflags gnome gnomeui` \
	  -o $@ gnome-ssh-askpass1.c \
		`gnome-config --libs gnome gnomeui`

ssh-askpass-gtk+2: gnome-ssh-askpass2.c
	$(CC) $(CFLAGS) `$(PKG_CONFIG_CFLAGS) gtk+-2.0` \
	  -o $@ gnome-ssh-askpass2.c \
	  `$(PKG_CONFIG_LIBS) gtk+-2.0 x11`

ssh-askpass-gtk+3: gnome-ssh-askpass2.c
	$(CC) $(CFLAGS) `$(PKG_CONFIG_CFLAGS) gtk+-3.0` \
	  -o $@ gnome-ssh-askpass2.c \
	  `$(PKG_CONFIG_LIBS) gtk+-3.0 x11`

clean:
	rm -f *.o gnome-ssh-askpass gnome-ssh-askpass[123]
	rm -f ssh-askpass-gnome ssh-askpass-gtk+[23]


#obsolete targets - still used in redhat/openssh.spec (TODO)
gnome-ssh-askpass1: ssh-askpass-gnome
	cp ssh-askpass-gnome $@

gnome-ssh-askpass2: ssh-askpass-gtk+2
	cp ssh-askpass-gtk+2 $@
