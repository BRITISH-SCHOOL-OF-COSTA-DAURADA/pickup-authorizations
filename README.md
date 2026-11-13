# Pickup authorizations

Lookup for after-school monitors: sign in, type a student's name and see their parents/guardians, the people authorised to collect them and today's notifications for that student (grouped by type, Collection first).

- `index.html` is the whole site. People sign in with their school APP (ERP) username and password; the page then reads the ERP directly, read-only, with that person's own session. Data is live and limited to what the person's APP profile allows.
- `.github/workflows/publish.yml` publishes the page to GitHub Pages on every push to `main`, plus a preview of the `dev` branch at `/dev/`.

The repository holds no data and no credentials. To give or remove someone's access, create or disable their APP account.
