# Pickup authorizations

Lookup for after-school monitors: type a student's name and see their parents/guardians and the people authorised to collect them.

- `build.mjs` reads the ERP (read-only), encrypts the data with the access key and generates `dist/`.
- `index.html` asks for the key, decrypts in the browser and searches locally.
- `.github/workflows/publish.yml` rebuilds it every hour during school hours and publishes it to GitHub Pages.

Repository secrets: `BSCD_ERP_USER`, `BSCD_ERP_PASS`, `PICKUP_ACCESS_KEY`.

Data is never stored in the repository and is only published encrypted. To change the access key, update `PICKUP_ACCESS_KEY` and run the workflow manually. A link of the form `https://…/pickup-authorizations/#<key>` signs a monitor in without typing.
