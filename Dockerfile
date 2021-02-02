FROM archlinux

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python

RUN git clone https://git.csames.de/colin/spki-cache-server.git

CMD ["/spki-cache-server/cache.py", "0.0.0.0", "8383", "-k", "/keys", "-v"]
