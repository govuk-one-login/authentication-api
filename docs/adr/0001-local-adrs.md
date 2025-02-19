# Storing Architectural Design Records (ADRs) within our repo

## Summary

We will store ADRs within the `/docs/adr` folder of this repository. These will log the architectural choices we have made, why, and consequences.

This will not duplicate [digital-identity-architecture](https://github.com/alphagov/digital-identity-architecture), as the intended audience and permissions models is different.

Strategic decisions, with cross programme consequence, will need to be in [digital-identity-architecture](https://github.com/alphagov/digital-identity-architecture) where architecture leads will review them.

Tactical decisions within the team, describing how we structure our services, are documented here and reviewed by the team's developers, architects, and tech leads.

## Context

ADRs with strategic implications are in [digital-identity-architecture](https://github.com/alphagov/digital-identity-architecture) need a review from a Lead Architect or Head of Architecture. Some may be also need review from the GOV.UK One Login Decision board (D3).

Teams have autonomy to design and deliver a solution within those goalposts.

We want a place to document the decisions made by our team which don't need a full cross-programme review.

The intended audience for these documents include:

- New developers to the team who are trying to understand our services.
- Developers from other teams curious to see our implementation and compare ideas.
- Developers within the team, looking for a reference architecture when delivering work.

## Format

We should keep formatting simple,

- Infer dates and authors from the Git history.
- Write in markdown.
- Aim to keep headings consistent with this PR, although they can vary if needed.
- A reviewed and merged ADR means that decision has been adopted.
- Deprecate superseded ADRs by amending them with "Status: superseded." A link referencing any new ADR or reason must be provided.

## Consequences

- We will store ADR records relating to `di-authentciation-api` in `docs/adr`
- Where there are cross program consequences, we may have a stub here, but it should point to a cross programme ADR in [digital-identity-architecture](https://github.com/alphagov/digital-identity-architecture)
- We will represent all current features with an ADR.
- Other repos will have their own `/docs/adr` folder with relevant ADRs stored there, next to the code.
