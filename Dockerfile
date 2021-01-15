FROM archlinux

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python

RUN git clone https://git.csames.de/colin/spki-cache-server.git \
    && mkdir /keys \
    && cd spki-cache-server \
    && ./gen-keys 100 /keys

CMD ["/spki-cache-server/cache.py", "0.0.0.0", "8383", "-k", "/keys", "-v"]
