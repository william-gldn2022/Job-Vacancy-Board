# Job-Vacancy-Board
A University Assignment Project

## What is it?
This project is a job vacancy board to be used for internal recruitment within an organisation. It is built for two different kind of users (Admin and Regular). Regular users have the power to conduct searches of all the available jobs, as well as manage their own account. Admin users have the same power as regular users, plus the power to manage the job adverts seen, as well as manage user accounts.

## Running the app
To run locally: 
- Make sure you are in a virtual environment.
```source venv/Scripts/activate```
- cd to the file location
- Install requirements
```pip install -r requirements.txt ```
- Run the app
```python -m flask --app server --debug run```

## To host on a server
By running server.py, by using a hosting service, the application will be deployable. Currently, the application is hosted on Render, using a free tier. 

## Dependancies 
All packagaes used are listed within the requirements.txt file.
As such, this web-app is built using Flask. The UI is built using HTML and Bootstrap. The database is an SQLite database, containing two unrelated tables.
