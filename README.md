# wopt

test audit de sécurité web en ligne de commande — non-intrusif, sans configuration, sans infrastructure.

`wopt` scanne un site web et vérifie les points de sécurité les plus fréquemment négligés : en-têtes HTTP, configuration TLS, cookies, CORS, et exposition de fichiers sensibles. Conçu pour s'intégrer facilement à un pipeline CI/CD.
## Auteurs

[eloundou nkolo ryan] (https://eloundounkolo.com)

## Installation

```bash
pip install wopt
```

Ou en local depuis le code source :

```bash
git clone https://github.com/eloundou-nkolo/wopt.git
cd wopt
pip install -r requirements.txt
pip install -e .
```

## Utilisation

```bash
# Scan simple, affichage table dans le terminal
wopt exemple.com

# Export JSON (pour CI/CD)
wopt exemple.com --format json --output rapport.json

# Export HTML lisible
wopt exemple.com --format html --output rapport.html

# Rapport formaté pour être collé dans un agent IA (Claude Code, Cursor...)
wopt exemple.com --ai-context

# Scan plus léger, sans vérification des chemins sensibles
wopt exemple.com --no-probes
```

## Ce que wopt vérifie

| Catégorie | Vérifications |
|---|---|
| **Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, divulgation de stack |
| **TLS** | Version du protocole, expiration du certificat, redirection HTTPS |
| **Cookies** | Flags Secure, HttpOnly, SameSite |
| **CORS** | Combinaison dangereuse wildcard + credentials |
| **Exposition** | Fichiers sensibles accessibles (`.env`, `.git/HEAD`, backups...) |

## Philosophie

- **100% passif et non-intrusif** : aucun scan de ports, aucune tentative d'exploitation, aucun brute-force. Uniquement des requêtes HTTP GET standards.
- **Zéro infrastructure** : tourne entièrement en local, aucune donnée envoyée à un serveur tiers.
- **Pensé pour l'ère du vibe coding** : conçu pour combler les lacunes de sécurité fréquentes dans le code généré par IA (absence de headers de sécurité, CSRF, CORS mal configuré).

## Score

Chaque scan produit un score de A à F, calculé par pondération de sévérité (inspiré de l'approche Mozilla Observatory).

## Développement

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

## Avertissement

`wopt` est un outil d'audit passif destiné à un usage sur des sites que vous possédez ou êtes autorisé à tester. L'auteur décline toute responsabilité en cas d'usage non autorisé.

## Licence

MIT
