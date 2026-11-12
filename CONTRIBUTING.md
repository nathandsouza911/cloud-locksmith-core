# Contributing

Thanks for your interest in Cloud Locksmith Core.

## Contributor License Agreement

Contributions are accepted under the Contributor License Agreement in `CLA.md`. There is
no CLA bot yet; by opening a pull request you agree to its terms. If a CLA check is added
later, a bot will ask you to confirm by replying with the sentence it gives you.
You keep the copyright in your contribution; the CLA lets the project distribute it under
the AGPL and under other licences.

## Before you open a pull request

* Keep changes focused; one topic per pull request.
* Tenant isolation is the first priority. Never take a tenant ID from client input
  without checking the user's access to it, and scope every query to the tenant.
* Add or update tests. Run the checks:

```
cd backend && ruff check . && ruff format --check . && pytest -q
cd dashboard && npm run lint && npm run typecheck && npm run format:check && npx jest
```

* If you change the control registry, regenerate `docs/controls.md`:
  `cd backend && python -m tools.gen_controls_doc > ../docs/controls.md`.
* Database changes go in a new Alembic revision. Revision IDs must be 32 characters or
  fewer (Postgres stores them in `VARCHAR(32)`), for example `20261201_add_widget`.
* Shell scripts must use LF line endings (`.gitattributes` enforces this).
* Never commit `.env` files, real tenant data, real names or email addresses. Use
  fictional data on the `.example` domain in tests.

## Code of conduct

This project follows the Contributor Covenant (`CODE_OF_CONDUCT.md`).
