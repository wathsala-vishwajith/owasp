# Broken Access Control - Backend

This is a SpringBoot REST API that demonstrates various broken access control vulnerabilities.

## Running the Application

```bash
./mvnw spring-boot:run
```

Or using Maven directly:

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`

## API Endpoints

### User Endpoints (All Vulnerable!)

- `GET /api/users` - List all users (should be admin-only)
- `GET /api/users/{id}` - Get user by ID (no ownership check)
- `POST /api/users` - Create new user (no validation)
- `PUT /api/users/{id}/salary` - Update salary (no authorization)
- `PUT /api/users/{id}/role` - Update role (no authorization)

### Admin Endpoints (No Admin Check!)

- `GET /api/admin/users` - List all users (no admin check)
- `DELETE /api/admin/users/{id}` - Delete user (no admin check)

### Utility

- `GET /api/current-user?userId=X` - Simulate logged-in user

## Sample Data

The application is initialized with 5 users:

1. **john_doe** (USER) - ID: 1
2. **jane_smith** (USER) - ID: 2
3. **bob_admin** (ADMIN) - ID: 3
4. **alice_user** (USER) - ID: 4
5. **charlie_manager** (USER) - ID: 5

## H2 Console

Access the H2 database console at: `http://localhost:8080/h2-console`

- JDBC URL: `jdbc:h2:mem:owaspdb`
- Username: `sa`
- Password: (leave empty)

## Testing the Vulnerabilities

### 1. IDOR - View Other Users' Data

```bash
# As user 1, view user 2's sensitive data
curl http://localhost:8080/api/users/2
```

### 2. Access Admin Endpoint as Regular User

```bash
# Regular user accessing admin endpoint
curl http://localhost:8080/api/admin/users
```

### 3. Modify Another User's Salary

```bash
# Update user 2's salary without authorization
curl -X PUT http://localhost:8080/api/users/2/salary \
  -H "Content-Type: application/json" \
  -d '{"salary": 999999}'
```

### 4. Promote Yourself to Admin

```bash
# Change your own role to ADMIN
curl -X PUT http://localhost:8080/api/users/1/role \
  -H "Content-Type: application/json" \
  -d '{"role": "ADMIN"}'
```

### 5. Delete Another User

```bash
# Delete user without admin check
curl -X DELETE http://localhost:8080/api/admin/users/2
```

## What's Wrong?

All endpoints lack proper authorization checks:

- No verification that the user is accessing their own data
- No role-based access control (RBAC)
- Admin endpoints accessible to all users
- No ownership verification for updates
- Missing authentication entirely

## How to Fix

See the main README for secure code examples using Spring Security.
