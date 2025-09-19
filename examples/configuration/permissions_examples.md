# Group-Based Permissions Configuration Examples

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