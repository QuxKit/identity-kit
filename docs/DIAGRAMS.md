# identity-kit — diagrams

The mermaid sources for this repo. They live here rather than in the
README because npm renders no mermaid: on the package page a fence
like this one ships as raw DSL. GitHub and the QuxKit docs site both
draw them. The README carries an ASCII equivalent of each.

## What identity-kit owns, and the two seams it hands out

```mermaid
flowchart LR
    cred(["credentials<br/>email + password"])

    subgraph IK["identity-kit — Apache-2.0"]
        direction LR
        ac["accounts<br/>signup · login · reset"]
        pw["credentials<br/>argon2id + pepper"]
        se["sessions<br/>server-side, revocable"]
        ac --> pw
        ac --> se
    end

    subgraph HOST["your app"]
        db[("your database<br/>identity schema")]
        mx["mail transport"]
    end

    cred --> ac
    se -->|UserId| out(["UserId"])
    IK -->|SqlExecutor| db
    ac -->|MailSender| mx

    classDef own fill:#0d9488,stroke:#0f766e,color:#ffffff;
    classDef host fill:#1e293b,stroke:#0f172a,color:#e2e8f0;
    class ac,pw,se own;
    class db,mx host;
    class cred,out host;
```

## Where identity-kit sits in the family

```mermaid
flowchart TB
    ik["identity-kit<br/>who you are + how you prove it"] -->|UserId| tk["tenant-kit<br/>what you belong to + isolation"]
    tk -->|tenantId| bk["billing-kit<br/>what you owe"]
    classDef a fill:#0d9488,stroke:#0f766e,color:#fff
    class ik a
```
