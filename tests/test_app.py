import unittest
from flask import url_for
from models import db, User, Job, bcrypt  # Import bcrypt from models
from __init__ import create_app

class BaseTestCase(unittest.TestCase):
    """A base test case for the Flask app."""

    def setUp(self):
        """Set up a blank temp database before each test."""
        self.app = create_app({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SECRET_KEY': 'test_secret_key',
            'WTF_CSRF_ENABLED': False,
            'SERVER_NAME': 'localhost:5000'  # Add SERVER_NAME
        })
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        """Destroy blank temp database after each test."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_example(self):
        """Example test to ensure the test setup works."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)


class TestModels(BaseTestCase):
    """Test cases for the database models."""

    def test_user_creation(self):
        """Test if a User is created correctly."""
        user = User(username="testuser", password=bcrypt.generate_password_hash("password").decode('utf-8'), role="User")
        db.session.add(user)
        db.session.commit()
        self.assertEqual(User.query.count(), 1)
        self.assertEqual(User.query.first().username, "testuser")

    def test_job_creation(self):
        """Test if a Job is created correctly."""
        job = Job(
            jobRole="Software Engineer",
            shortDescription="Develop software",
            longDescription="Develop and maintain software",
            salary=60000,
            location="New York",
            grade="Senior"
        )
        db.session.add(job)
        db.session.commit()
        self.assertEqual(Job.query.count(), 1)
        self.assertEqual(Job.query.first().jobRole, "Software Engineer")


class TestViews(BaseTestCase):
    """Test cases for the views/routes."""

    def test_index_page_loads(self):
        """Test that the index page loads correctly."""
        with self.app.test_request_context():
            response = self.client.get(url_for('main.index'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Login', response.data)  # Check if the page contains 'Login'

    def test_login(self):
        """Test user login functionality."""
        # First, create a user in the database using bcrypt to hash the password
        hashed_password = bcrypt.generate_password_hash("password").decode('utf-8')
        user = User(username="testuser", password=hashed_password, role="User")
        db.session.add(user)
        db.session.commit()

        with self.app.test_request_context():
            # Attempt to login with the created user
            response = self.client.post(url_for('main.index'), data=dict(
                username='testuser',
                password='password',
                login='Login'
            ), follow_redirects=True)

            self.assertIn(b'Logout', response.data)  # Check if the login was successful


class TestUtilityFunctions(BaseTestCase):
    """Test cases for utility functions."""

    def test_validate_password(self):
        """Test password validation utility function."""
        from main import validate_password
        self.assertIsNone(validate_password("Valid1Password!"))
        self.assertIsNotNone(validate_password("short"))
        self.assertEqual(validate_password("short"), "Password needs to be at least 8 characters long.")
        self.assertEqual(validate_password("alllowercase1!"), "Password needs to contain at least one uppercase letter.")

class TestUserRegistration(BaseTestCase):
    """Test cases for user registration functionality."""

    def test_register_user(self):
        """Test registering a new user."""
        with self.app.test_request_context():
            response = self.client.post(url_for('main.index'), data=dict(
                username='newuser',
                password='Valid1Password!',
                confirm_password='Valid1Password!',
                role='User',
                register='Register'  # Simulate the register button being pressed
            ), follow_redirects=True)
            
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Logout', response.data)  # Check for 'Logout' to confirm registration success

            # Check if the user is actually added to the database
            user = User.query.filter_by(username='newuser').first()
            self.assertIsNotNone(user)
            self.assertEqual(user.username, 'newuser')

    def test_register_duplicate_user(self):
        """Test that duplicate usernames cannot be registered."""
        with self.app.test_request_context():
            # Create a user in the database
            user = User(username="duplicateuser", password=bcrypt.generate_password_hash("password").decode('utf-8'), role="User")
            db.session.add(user)
            db.session.commit()

            # Attempt to register with the same username
            response = self.client.post(url_for('main.index'), data=dict(
                username='duplicateuser',
                password='Valid1Password!',
                confirm_password='Valid1Password!',
                role='User',
                register='Register'
            ), follow_redirects=True)
            
            self.assertIn(b'Username already taken. Please choose a different one.', response.data)

class TestAdminFunctions(BaseTestCase):
    """Test cases for admin-specific functionality."""

    def test_admin_access(self):
        """Test that admin-only pages are protected and accessible by admins."""
        # First, create an admin user and login
        admin_password = bcrypt.generate_password_hash("adminpassword").decode('utf-8')
        admin_user = User(username="admin", password=admin_password, role="Admin")
        db.session.add(admin_user)
        db.session.commit()

        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='admin',
                password='adminpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.get(url_for('main.advert_management'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Advert Management', response.data)  # Check for page-specific content

    def test_non_admin_access(self):
        """Test that non-admin users are denied access to admin-only pages."""
        # First, create a normal user and login
        user_password = bcrypt.generate_password_hash("userpassword").decode('utf-8')
        user = User(username="normaluser", password=user_password, role="User")
        db.session.add(user)
        db.session.commit()

        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='normaluser',
                password='userpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.get(url_for('main.advert_management'), follow_redirects=True)
            self.assertIn(b'You do not have permission to access this page.', response.data)

class TestJobManagement(BaseTestCase):
    """Test cases for job management functionality."""

    def test_add_job(self):
        """Test adding a new job listing."""
        # Create an admin user and login
        admin_password = bcrypt.generate_password_hash("adminpassword").decode('utf-8')
        admin_user = User(username="admin", password=admin_password, role="Admin")
        db.session.add(admin_user)
        db.session.commit()

        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='admin',
                password='adminpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.post(url_for('main.add_job'), data=dict(
                jobRole='Test Engineer',
                shortDescription='Testing software',
                longDescription='Detailed description for Test Engineer position.',
                grade='Mid-level',
                location='Remote',
                salary=70000
            ), follow_redirects=True)

            self.assertIn(b'Job added successfully!', response.data)
            job = Job.query.filter_by(jobRole='Test Engineer').first()
            self.assertIsNotNone(job)
            self.assertEqual(job.jobRole, 'Test Engineer')

    def test_edit_job(self):
        """Test editing an existing job listing."""
        # Create an admin user and login
        admin_password = bcrypt.generate_password_hash("adminpassword").decode('utf-8')
        admin_user = User(username="admin", password=admin_password, role="Admin")
        db.session.add(admin_user)
        db.session.commit()

        # Add a job to the database
        job = Job(jobRole='Developer', shortDescription='Develop software', longDescription='Detailed description for Developer', grade='Junior', location='NY', salary=60000)
        db.session.add(job)
        db.session.commit()

        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='admin',
                password='adminpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.post(url_for('main.edit_job', job_id=job.id), data=dict(
                jobRole='Updated Developer',
                shortDescription='Develop software',
                longDescription='Updated description for Developer',
                grade='Junior',
                location='NY',
                salary=65000
            ), follow_redirects=True)

            self.assertIn(b'Job updated successfully!', response.data)
            updated_job = Job.query.get(job.id)
            self.assertEqual(updated_job.jobRole, 'Updated Developer')
            self.assertEqual(updated_job.salary, 65000)

    def test_delete_job(self):
        """Test deleting a job listing."""
        # Create an admin user and login
        admin_password = bcrypt.generate_password_hash("adminpassword").decode('utf-8')
        admin_user = User(username="admin", password=admin_password, role="Admin")
        db.session.add(admin_user)
        db.session.commit()

        # Add a job to the database
        job = Job(jobRole='Tester', shortDescription='Test software', longDescription='Detailed description for Tester', grade='Junior', location='SF', salary=50000)
        db.session.add(job)
        db.session.commit()

        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='admin',
                password='adminpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.post(url_for('main.delete_job', job_id=job.id), follow_redirects=True)

            self.assertIn(b'Job deleted successfully!', response.data)
            deleted_job = Job.query.get(job.id)
            self.assertIsNone(deleted_job)

class TestSearchFunctionality(BaseTestCase):
    """Test cases for job search functionality."""

    def test_search_jobs(self):
        """Test searching for jobs with specific criteria."""
        # Create an admin user and login
        admin_password = bcrypt.generate_password_hash("adminpassword").decode('utf-8')
        admin_user = User(username="admin", password=admin_password, role="Admin")
        db.session.add(admin_user)
        db.session.commit()

        # Add jobs to the database
        job1 = Job(jobRole='Backend Developer', shortDescription='Backend work', longDescription='Develop backend systems', grade='Senior', location='New York', salary=120000)
        job2 = Job(jobRole='Frontend Developer', shortDescription='Frontend work', longDescription='Develop frontend interfaces', grade='Junior', location='San Francisco', salary=80000)
        db.session.add_all([job1, job2])
        db.session.commit()


        with self.app.test_request_context():
            self.client.post(url_for('main.index'), data=dict(
                username='admin',
                password='adminpassword',
                login='Login'
            ), follow_redirects=True)

            response = self.client.get(url_for('main.results'), query_string=dict(
                jobRole='Backend Developer',
            ), follow_redirects=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Backend Developer', response.data)

if __name__ == '__main__':
    unittest.main()
