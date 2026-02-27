# Online Internship Management Portal

A comprehensive web-based platform designed to streamline the internship lifecycle, from application to certification. This system features multiple user roles and an automated workflow for managing internships, supervisors, students, and tasks.

## 🚀 Features

- **Multi-Role Authentication**: Secure login for Super Admins, Company Admins, Supervisors, and Students.
- **Workflow Automation**: Automated approval processes and email notifications.
- **Internship Management**: Companies can post internships and hire supervisors.
- **Task Management**: Supervisors can assign tasks; students can submit work for review.
- **Certificate Generation**: Automatic PDF certificate generation upon internship completion.
- **Responsive UI**: Modern, user-friendly interface for all dashboards.

## 🛠️ Technology Stack

- **Backend**: Python (Flask)
- **Database**: MySQL (via XAMPP/MySQL Workbench)
- **Object-Relational Mapping**: SQLAlchemy
- **Security**: Flask-Bcrypt (Password Hashing)
- **Email**: Flask-Mail (SMTP Integration)
- **Frontend**: HTML5, CSS3, JavaScript (Bootstrap/Vanilla CSS)

## 📂 Project Structure

- `app.py`: Main application logic and routing.
- `config.py`: Configuration settings (Database, Mail, Sessions).
- `models/`: Database models (User, Internship, Task, Submission, etc.).
- `templates/`: HTML templates for different user roles.
- `static/`: CSS, JS, and uploaded files.
- `database_schema.sql`: Database export for easy setup.

## ⚙️ Installation & Setup

### 1. Prerequisites
- Python 3.x installed.
- MySQL server (e.g., via XAMPP).

### 2. Clone the Project
```bash
git clone <repository-url>
cd Internship_portal
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Database Setup
1. Open XAMPP and start **Apache** and **MySQL**.
2. Go to `phpMyAdmin` (usually `http://localhost/phpmyadmin`).
3. Create a new database named `internship_portal_db`.
4. Import the `database_schema.sql` file provided in the project root.

### 5. Configuration
Update `config.py` with your MySQL credentials and Email SMTP settings.

### 6. Run the Application
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

## 🌐 Live Hosting Recommendations
For hosting this project online for free (no credit card required), we recommend:
1. **[PythonAnywhere](https://www.pythonanywhere.com/)**: Best for Python + MySQL projects.
2. **[Render](https://render.com/)**: Best for automatic deployment from GitHub.

## 👥 User Roles & Login

| Role | Username | Password |
| :--- | :--- | :--- |
| **Super Admin** | `SuperAdmin` | `admin123` |
| **Company Admin** | `Google` | `admin123` |
| **Supervisor** | `Dr_Smith` | `admin123` |
| **Student** | `Ahmad` | `admin123` |

## NOTICE📌
Dear Applicant's,

Please find the required files uploaded to the designated folder:

1. **Folder Zip File**: The complete folder has been zipped and uploaded.
2. **Date-base Zip File**: The date-base has also been zipped and uploaded.
3. **Project Screen Recording**: A complete screen recording of the project has been uploaded.
4. **Project Hosting**: The project is also live on Free Hosting Vercel, Infinity Free, or any other platform.

If you encounter any issues, kindly let us know.

**Folder Link**: [Google Drive Folder](https://drive.google.com/drive/folders/1G14KY3WqQpRDMh8nkLm4S_4SBVS9DhxX)

---
*Developed as part of the Internship Management System project.*
