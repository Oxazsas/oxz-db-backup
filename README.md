# OXZ DB Backup

**OXZ DB Backup** est une suite de scripts Bash robuste pour gérer la sauvegarde, la restauration et la rétention de bases de données MySQL/MariaDB (supporte `Docker` et `Local`).
Les sauvegardes sont **compressées** (`zstd`) et **chiffrées** (`age`) avant d'être synchronisées vers un stockage distant via `rsync`.

## 📦 Fonctionnalités

- **Assistants Interactifs** : Configuration guidée pour créer, modifier et tester des jobs de sauvegarde.
- **Sécurité** : Chiffrement moderne avec [age](https://github.com/FiloSottile/age). Les clés privées ne sont pas stockées sur le serveur de production (sauf temporairement lors d'une restauration manuelle).
- **Compression** : Utilisation de `zstd` pour des sauvegardes rapides et compactes.
- **Support Docker & Local** : Détection intelligente des instances MySQL (conteneurs ou service système).
- **Rétention Avancée** : Gestion fine de la politique de rétention (locale et distante).
- **Notifications** : Support des Webhooks (Discord, Slack, etc.) pour le suivi des succès/échecs.
- **Restauration Sécurisée** : Script dédié pour restaurer des dumps chiffrés avec vérifications d'intégrité avant toute action destructive.

## 📂 Architecture

La suite se compose de trois scripts principaux :

1.  **`db-backup-wizard.sh`** :

    - Interface principale pour gérer les jobs (CRUD).
    - Génération des clés de chiffrement `age`.
    - Tests de connexion DB et Rsync.
    - Pont vers le runner et le restore.

2.  **`db-backup-runner.sh`** :

    - Exécute les tâches de sauvegarde (conçu pour être lancé par **Cron**).
    - Gère le dump, la compression, le chiffrement, et le rsync.
    - Applique les politiques de nettoyage (rétention).
    - Envoie les notifications Webhook.
    - Mode interactif disponible pour forcer un run manuel.

3.  **`db-backup-restore.sh`** :
    - Assistant de restauration.
    - Déchiffre et décompresse les dumps à la volée.
    - Clone les permissions utilisateurs si nécessaire.
    - Sécurité : demande la clé privée de manière interactive (jamais stockée sur le disque de manière persistante).

## 🚀 Installation

### Prérequis

Assurez-vous que les outils suivants sont installés sur votre serveur (Ubuntu/Debian) :

```bash
sudo apt update
sudo apt install -y bash curl jq rsync zstd age mysql-client
```

### Mise en place

1.  Clonez ce dépôt :

    ```bash
    git clone https://github.com/Oxazsas/oxz-db-backup.git
    cd oxz-db-backup
    ```

2.  Lancez l'installateur :

    ```bash
    chmod +x install.sh
    sudo ./install.sh
    ```

    L'installateur va :

    - Vérifier les dépendances
    - Créer les dossiers système (`/etc/oxz-db-backup`, `/var/lib/oxz-db-backup`, etc.)
    - Installer les scripts dans `/usr/local/lib/oxz-db-backup/`
    - Créer la commande `oxz-db-backup` (et l'alias `oxzbkp`)
    - Configurer logrotate
    - Migrer automatiquement une ancienne installation `db-backup` si détectée

## 📖 Utilisation

Note : Tous les scripts doivent être exécutés en tant que `root` (ou avec `sudo`) car ils écrivent dans `/etc/oxz-db-backup` et `/var/backups/oxz-db-backup`.

### 1. Configuration (Wizard)

Lancez l'assistant pour créer votre premier job de sauvegarde :

```bash
sudo oxz-db-backup
```

Suivez les instructions à l'écran pour :

- Définir le nom du job.
- Choisir la source (Docker ou Local).
- Configurer les accès MySQL.
- Définir la destination Rsync.
- Configurer la rétention et le Webhook.

### 2. Automatisation (Cron)

Le `runner` est fait pour tourner automatiquement. Le wizard peut configurer le cron pour vous (option "Runner" > "Installer cron"), ou vous pouvez l'ajouter manuellement :

```bash
# /etc/cron.d/oxz-db-backup
0 * * * * root /usr/local/lib/oxz-db-backup/db-backup-runner.sh --cron >> /var/log/oxz-db-backup/cron.log 2>&1
```

Vous pouvez aussi lancer le runner manuellement pour voir l'état des jobs :

```bash
sudo /usr/local/lib/oxz-db-backup/db-backup-runner.sh
```

### 3. Restauration

Pour restaurer une sauvegarde :

```bash
sudo /usr/local/lib/oxz-db-backup/db-backup-restore.sh
```

Il vous sera demandé de coller votre **clé privée** `age` (celle générée lors de la création du job). Le script s'occupe du reste.

## 📁 Structure des fichiers

- **Configuration** : `/etc/oxz-db-backup/jobs/*.json`
- **Clés publiques** : `/etc/oxz-db-backup/keys/*.pub`
- **Secrets** : `/etc/oxz-db-backup/secrets/` (Credentials obfusqués)
- **Sauvegardes** : `/var/backups/oxz-db-backup/`
- **Logs** : `/var/log/oxz-db-backup/`

## ⚠️ Notes de sécurité

- **Clés Privées** : Le wizard génère une paire de clés. La clé publique est stockée sur le serveur pour chiffrer les backups. **La clé privée vous est affichée UNE SEULE FOIS.** Vous devez la sauvegarder en lieu sûr (gestionnaire de mots de passe). Sans elle, les backups sont irrécupérables.
- **Permissions** : Les dossiers de configuration et de logs sont restreints à `root`.
- **SSH Distant** : Avant de configurer un backup distant (rsync/ssh), connectez-vous **manuellement** une première fois au serveur cible pour valider son empreinte SSH :
  ```bash
  ssh user@remote-server
  # Acceptez l'empreinte, puis déconnectez-vous
  ```
  Cela évite les risques d'attaque MITM lors de la première connexion automatisée.

## License

Voir le fichier [LICENSE](./LICENSE).
