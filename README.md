# graphql-authz-proxy

Proxy to enforce authorization rules on GraphQL APIs.

## Features

- Enforces fine-grained authorization for GraphQL queries and mutations
- Supports config-driven user/group/policy management
- Easy integration with existing GraphQL servers

## Usage

### Running the Proxy

You can run the proxy using the CLI:

```bash
gqlproxy start --upstream-url <UPSTREAM_GRAPHQL_URL> --users-config <users.yaml> --groups-config <groups.yaml>
```

Or with Docker:

```bash
docker run -p 8080:8080 \
  -v $(pwd)/users.yaml:/app/users.yaml \
  -v $(pwd)/groups.yaml:/app/groups.yaml \
  kgmcquate/graphql-authz-proxy:latest \
  --upstream-url <UPSTREAM_GRAPHQL_URL> --users-config /app/users.yaml --groups-config /app/groups.yaml
```

## Configuration

### Users Config

```yaml
users:
  - email: "kgmcquate@gmail.com"
    username: "kgmcquate"
    groups:
      - "admin"
  - email: "bob@company.com"
    username: "bob"
    groups:
      - "viewers"
```

### Groups Config

```yaml
groups:
  - name: "admin"
    description: "Full administrative access"
    permissions:
      mutations:
        effect: "allow"
        fields:
          - field_name: "*"
      queries:
        effect: "allow"
        fields:
          - field_name: "*"

  - name: "engineering"
    description: "Less restrictive permissions for dev testing"
    permissions:
      mutations:
        effect: "allow"
        fields:
          - field_name: "user"
            arguments:
              - argument_name: "name"
                values: ["Ann Berry"]
            fields:
              - field_name: first_name
              - field_name: last_name
              - field_name: user_id
      queries:
        effect: "allow"
        fields:
          - field_name: "*"

  - name: "viewers"
    description: "Read-only access"
    permissions:
      mutations:
        effect: "deny"
        fields:
          - field_name: "*"
      queries:
        effect: "allow"
        fields:
          - field_name: "user"
            arguments:
              - argument_name: "name"
                values: ["Ann"]
```

## GraphQL Query Examples: Allowed vs Denied

Below are example queries and their authorization results for the `viewers` and `engineering` groups:

### Example 1: Allowed for viewers

**Query:**

```graphql
query {
  user(name: "Ann") {
    first_name
    last_name
    user_id
  }
}
```

**Result:** Allowed for `viewers` (matches field and argument restriction)

### Example 2: Denied for viewers

**Query:**

```graphql
query {
  user(name: "Bob") {
    first_name
    last_name
    user_id
  }
}
```

**Result:** Denied for `viewers` (argument `name: "Bob"` not allowed)

### Example 3: Allowed for engineering

**Query:**

```graphql
mutation {
  user(name: "Ann Berry") {
    first_name
    last_name
    user_id
  }
}
```

**Result:** Allowed for `engineering` (mutation on `user` with allowed argument and fields)

### Example 4: Denied for engineering

**Query:**

```graphql
mutation {
  user(name: "Ann Berry") {
    email
    phone
  }
}
```

**Result:** Denied for `engineering` (fields `email` and `phone` not allowed)

### Example 5: Denied for viewers (mutation)

**Query:**

```graphql
mutation {
  user(name: "Ann") {
    first_name
  }
}
```

**Result:** Denied for `viewers` (all mutations denied)

## Notes

- All config files must be valid YAML and match the schema above.
- `field_name: "*"` means all fields/operations are allowed/denied.

## License

MIT