FROM archlinux/base

RUN pacman -Sy archlinux-keyring --noconfirm \
    && pacman -Syyu --noconfirm \
    && pacman -S --noconfirm --needed git python

RUN git clone https://git.csames.de/colin/rpki-cache.git \
    && mkdir /keys \
    && cd rpki-cache \
    && ./gen-keys 100 /keys

CMD ["/rpki-cache/cache.py", "0.0.0.0", "8383", "-k", "/keys", "-v"]
