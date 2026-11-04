# Healthy Weight, Healthy Life

ระบบบันทึกน้ำหนักพนักงาน STAR LIVE ONLINE

## Architecture

- Frontend: GitHub Pages (`index.html`, `starlive-logo.png`)
- Public URL: https://healthy-weight.starlive-s.com/
- API: Cloudflare Worker `spring-shadow-65fe` (`worker.js`)
- Database: Cloudflare D1 `healthy-weight-db`
- D1 binding: `DB`

## Deploy Worker

Install Wrangler and authenticate with Cloudflare, then run:

```bash
npx wrangler deploy
```

The `wrangler.toml` file maps the Worker binding `DB` to the existing D1 database. Do not commit credentials, API tokens, employee passwords, or exported production data.

## API actions

- `login`: authenticate employee and return profile and weight history
- `register`: activate an employee account
- `submitWeight`: verify employee credentials and save weight plus compressed image evidence

Legacy plaintext passwords are upgraded to PBKDF2 hashes on successful login. New registrations use PBKDF2 hashes.

## Database tables

- `employees`
- `weight_logs`

The existing production database is retained; no tables or employee records are dropped by this project.
