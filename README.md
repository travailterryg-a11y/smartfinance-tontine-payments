# Serveur de paiement en ligne — SmartFinance

Petit serveur Node.js independant (PAS un module Flutter) qui gere tous les
paiements en ligne de l'app (cotisations de tontine + abonnement Premium)
via E-Billing (Digitech Africa). Il existe parce que le `client_secret`
E-Billing ne doit jamais etre integre dans l'app mobile, et que Firebase
Cloud Functions (l'alternative naturelle) exige le plan payant Blaze.

**Reecrit a partir de la vraie spec OpenAPI** du compte marchand
(`lab.billing-easy.net/api-docs/v1/swagger.yaml`), pas d'une supposition —
elle a revele un fonctionnement different de ce qu'on trouve dans les
integrations les plus anciennes en ligne :

- **Authentification** : OAuth2 client-credentials (`client_id`/
  `client_secret` → `POST /oauth/token` → jeton Bearer), pas de Basic Auth
  Username/SharedKey (celle-ci n'est acceptee que 3 mois, en legacy, et
  bypasse les controles de scope).
- **Mobile money** : pas de page de paiement a ouvrir dans une WebView. On
  cree une facture (invoice), puis on declenche un **push USSD** —
  E-Billing envoie directement une invite de paiement sur le telephone du
  payeur, qui valide depuis son propre menu operateur (Airtel Money / Moov
  Money). L'app attend juste la confirmation via Firestore.
- **Carte bancaire** (CyberSource "Unified Checkout") : necessite d'heberger
  le SDK JS CyberSource sur une page web — **non implemente ici**, mobile
  money uniquement pour l'instant.

## Ce qu'il fait

### Tontines

1. **Initier un paiement** (`POST /api/tontine/init-payment`) : l'app appelle
   cette route une fois que le participant a choisi son operateur et
   renseigne son numero. Le serveur lit le montant reel de la cotisation
   directement dans Firestore (jamais depuis l'app), cree une facture chez
   E-Billing, puis declenche immediatement le push USSD sur le telephone du
   payeur.
2. **Webhook E-Billing** (`POST /api/tontine/ebilling/notify`) : appelee par
   E-Billing quand le paiement change d'etat. Le serveur ne fait JAMAIS
   confiance a ce contenu brut : il re-interroge E-Billing (`GET
   /api/v2/merchant/ussd_push/{id}`) pour confirmer l'etat reel avant
   d'ecrire quoi que ce soit, puis cree la cotisation dans Firestore avec le
   statut `verified`.
3. **Reversement au beneficiaire** (`POST /api/tontine/payout`) : NON
   IMPLEMENTE (voir "Hors scope" plus bas).

### Abonnement Premium

4. **Initier un paiement** (`POST /api/premium/init-payment`) : meme
   principe que les tontines, mais le prix vient d'une table fixe cote
   serveur (`PREMIUM_PLANS` dans `server.js` — 3000 FCFA/mois, 35000
   FCFA/an). Facture en XAF (zone CEMAC/Gabon) pour l'instant — pas de
   conversion par pays declare, une vraie tarification multi-devises est une
   decision produit a part entiere.
5. **Webhook E-Billing** (`POST /api/premium/ebilling/notify`) : re-verifie
   le paiement, puis ecrit `premium: true` et `premiumExpireAt` sur le
   document `users/{uid}` via Admin SDK — les regles Firestore interdisent
   explicitement au client d'ecrire ces deux champs lui-meme (voir
   `firestore.rules`), donc ce serveur est le SEUL endroit qui peut faire
   passer un compte en Premium. Si l'utilisateur a deja un abonnement actif,
   prolonge depuis sa date d'expiration actuelle (renouvellement anticipe).

## Ce que tu dois faire toi-meme (je ne peux pas le faire a ta place)

### 1. Compte E-Billing
- Ouvre un compte (le bac a sable "lab" d'abord) aupres de Digitech Africa :
  https://www.digitech-africa.com/ebilling/
- Une fois inscrit : onglet **API credentials** de ton tableau de bord →
  recupere `Client ID` et `Client secret` (le secret ne s'affiche qu'une
  fois, a la creation ou apres "Regenerate").
- Dans les parametres de ton compte marchand, configure ton URL de
  notification (`notification_url`) vers
  `https://<ton-url-render>/api/tontine/ebilling/notify` pour les tontines,
  et une seconde config similaire vers `/api/premium/ebilling/notify` pour
  Premium (si ton compte ne permet qu'UNE SEULE URL de notification globale,
  utilise plutot celle des tontines partout et adapte le routage — a valider
  selon ce que permet ton tableau de bord).
- Cherche aussi si le tableau de bord expose une **cle de signature des
  webhooks** (distincte du `client_secret`) — colle-la dans
  `EBILLING_WEBHOOK_SIGNING_KEY` si tu la trouves. Sans elle, la
  re-verification via l'endpoint `GET` d'enquete reste active de toute
  facon (voir le commentaire en tete de `server.js`).

### 2. Compte de service Firebase
- Console Firebase > Parametres du projet > Comptes de service > "Generer
  une nouvelle cle privee" (bouton en bas). Un fichier JSON se telecharge.
- Tu n'as PAS besoin du plan Blaze pour ca : le compte de service et l'Admin
  SDK sont disponibles sur le plan gratuit Spark, seuls Cloud Functions et
  Storage l'exigent.
- Ouvre ce fichier JSON, copie tout son contenu, colle-le comme valeur de
  `FIREBASE_SERVICE_ACCOUNT` dans ton `.env` (tout sur une seule ligne).

### 3. Deploiement gratuit (Render, recommande)
1. Cree un compte sur https://render.com.
2. "New +" > "Web Service" > connecte ce depot (ou pousse juste le dossier
   `payment_backend/` dans un depot Git separe).
3. Render detecte Node automatiquement. Renseigne :
   - Build command : `npm install`
   - Start command : `npm start`
4. Dans l'onglet "Environment", ajoute toutes les variables de
   `.env.example` avec tes vraies valeurs (laisse `EBILLING_ENV=lab` tant
   que le compte n'est pas valide en production).
5. Une fois deploye, Render te donne une URL du type
   `https://smartfinance-pay.onrender.com` — mets cette URL dans
   `PUBLIC_BACKEND_URL` (redeploie apres l'avoir ajoutee), donne-la a l'app
   Flutter via `--dart-define=PAYMENT_BACKEND_URL=https://smartfinance-pay.onrender.com`,
   et configure les URLs de notification dans le tableau de bord E-Billing
   (voir etape 1).

Note sur le plan gratuit Render : le service se met en veille apres 15 min
d'inactivite et met quelques secondes a se reveiller au premier appel — sans
consequence ici puisque l'app attend deja la confirmation via Firestore.

### 4. Test local (optionnel avant de deployer)
```bash
cd payment_backend
npm install
cp .env.example .env
# remplis .env avec tes vraies valeurs (EBILLING_ENV=lab pour tester)
npm start
```
Pour qu'E-Billing puisse t'atteindre en local, utilise un tunnel (ex.
`ngrok http 3000`) et mets l'URL ngrok dans `PUBLIC_BACKEND_URL`, puis
reconfigure temporairement tes URLs de notification dessus le temps du test.

## Securite — ce qui est deja fait

- Le `client_secret` E-Billing ne quitte jamais ce serveur ; le jeton OAuth2
  qu'il permet d'obtenir est mis en cache en memoire, jamais persiste.
- Le webhook re-verifie chaque paiement aupres d'E-Billing (`GET
  /api/v2/merchant/ussd_push/{id}`) avant d'ecrire quoi que ce soit —
  protection contre un faux appel webhook forge par un tiers, meme sans la
  cle de signature optionnelle configuree.
- Verification de signature HMAC-SHA256 (`X-Signature`) en defense
  supplementaire quand `EBILLING_WEBHOOK_SIGNING_KEY` est renseignee.
- Le montant est toujours derive cote serveur (Firestore pour les tontines,
  table fixe pour Premium), jamais envoye par l'app.
- Idempotence : un meme paiement confirme deux fois par E-Billing (retries)
  ne cree/ne prolonge jamais deux fois.

## Hors scope pour l'instant

- **Paiement par carte** (Visa/Mastercard via CyberSource Unified Checkout) —
  necessite d'heberger le SDK JS CyberSource sur une page web et de gerer un
  "capture context" ; architecture differente du push USSD, pas traitee ici.
- **Reversement automatique aux beneficiaires de tontine (PAYOUT)** — la
  spec obtenue declare les tags "Payouts"/"Cash-in"/"KYC"/"Account" mais ne
  liste aucun endpoint pour eux (scopes probablement non accordes a ce
  compte). `POST /api/tontine/payout` repond une erreur explicite (501)
  plutot que de deviner des noms d'endpoint. En attendant, le systeme
  existant reste disponible en parallele : chaque beneficiaire renseigne ses
  coordonnees de reception dans l'app, et les autres participants peuvent
  toujours payer manuellement puis televerser une preuve (bouton "J'ai
  payé"), verifiee par un humain.
