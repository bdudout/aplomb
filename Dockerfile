# Aplomb — image du service (`aplomb serve`). Construction en deux étapes ; l'image finale
# ne contient que le binaire, sans shell, et tourne en utilisateur non root (EF-S5).
FROM rust:1.85-slim-bookworm AS construction
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY profils ./profils
RUN cargo build --release --locked -p aplomb

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=construction /src/target/release/aplomb /usr/local/bin/aplomb
USER nonroot
EXPOSE 7700 7701
ENTRYPOINT ["/usr/local/bin/aplomb"]
