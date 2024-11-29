

## Watch the walkthrough of the application here

[![Video Preview](https://img.youtube.com/vi/NAdHNfT3YM4/maxresdefault.jpg)](https://youtu.be/NAdHNfT3YM4)


## Prerequisites

- Python 3.7 or later
- Flask and dependencies

## Installation

1. Clone the repository
2. Create a `.env` file with the following variables:
   ```
   SECRET_KEY=your_secret_key
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=admin_password
   MODERATOR_EMAIL=moderator@example.com
   MODERATOR_PASSWORD=moderator_password
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Quick Start

Run the application:
```
python3 app.py
```

## Endpoints Overview

### Public Endpoints
- `GET /`: Home page with all articles
- `GET/POST /login`: User login (auto-creates admin/moderator accounts)
- `GET/POST /register`: User registration

### Authenticated Endpoints
- `GET /logout`: Log out current user
- `GET/POST /post`: Create an article (logged-in users)

### Moderator/Administrator Endpoints
- `GET /delete_article`: View articles for deletion
- `POST /delete_article/<id>`: Delete specific article

### Administrator-Only Endpoints
- `GET/POST /admin`: Admin dashboard for user management
- `POST /delete_user/<id>`: Delete user
- `POST /edit_role/<id>`: Change user role (user, moderator, admin)

## Roles
- **User**: Can view and post articles
- **Moderator**: Can delete articles
- **Admin**: Full system management

## Security
- JWT authentication
- Role-based access control
- Secure environment variable management

