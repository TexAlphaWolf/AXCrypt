# Politica di sicurezza

## Versioni supportate

| Versione | Supportata |
|----------|------------|
| 0.5.x    | ✅         |
| < 0.5    | ❌         |

## Segnalare una vulnerabilità

**Non aprire una issue pubblica per le vulnerabilità di sicurezza.**

Usa la segnalazione privata di GitHub: scheda **Security → Report a vulnerability**
(GitHub Private Vulnerability Reporting). In alternativa, contatta in privato il
titolare del progetto.

Nella segnalazione indica:

- una descrizione del problema e del possibile impatto;
- i passi per riprodurlo (proof-of-concept se possibile);
- la versione interessata e l'ambiente.

Tempi indicativi: presa in carico entro pochi giorni, aggiornamenti periodici
fino alla risoluzione.

## Ambito

AXCrypt usa primitive crittografiche standard e verificate (XChaCha20-Poly1305,
Argon2id, Ed25519, BLAKE3). Sono particolarmente graditi i report su:

- errori nella costruzione del formato o nell'uso dell'AEAD (nonce, AAD, tag);
- problemi nella derivazione o gestione delle chiavi (keyslot, MFK, zeroize);
- bug di parsing sfruttabili aprendo un archivio malevolo;
- aggiramenti della verifica della firma o del controllo di integrità.

Non rientrano nell'ambito: la robustezza di password deboli scelte dall'utente,
attacchi che richiedono il possesso simultaneo di password e keyfile, e
compromissioni del sistema operativo su cui gira il programma.
