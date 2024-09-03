"""
File : app.py
Author : Amelia Goldsby
Date Created : 21/08/2024
Project : ISA Recommendation Website
Course : Software Engineering and Agile
         Level 5, QA 

Description : This file is the main basis for the whole ISA Recommendation Website, 
              and contains the main functionalities, like configrations of the app routes, 
              and creation of the database isaDetails.db. CRUD operations are defined here, 
              allowing regular users to create, read, and update, and admin users to complete 
              the ssme operations, as well as delete.
"""

#Imports neccessary for all app route functionalities to work
from sqlite3 import IntegrityError
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
import crypt 

# Initialize the Flask application
app = Flask(__name__)

# Configuration for Database location and secret key for sessions
app.config['SECRET_KEY'] = 'your_secret_key'

# Use the environment variable DATABASE_URL if available; otherwise, use SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://default:U3oagGiR7HcT@ep-delicate-dew-a4quxafl.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy database object
db = SQLAlchemy(app)
app.app_context().push()

# ISARecommendations.db Tables (Becker, 2023)
# Defines User model for db
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f'<User {self.username}>'

# Defines Projections model for db
class Projections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deposit = db.Column(db.Float, nullable=False)
    monthlyPayment = db.Column(db.Float, nullable=False)
    years = db.Column(db.Integer, nullable=False)
    savings = db.Column(db.Boolean, nullable=False)
    highDebt = db.Column(db.Boolean, nullable=False)
    changes = db.Column(db.Boolean, nullable=False)
    riskRatingCount = db.Column(db.Integer, nullable=False)
    riskRating = db.Column(db.String(20), nullable=False)
    projectionAmount = db.Column(db.Float, nullable=True)
    projectionRiskAmount = db.Column(db.Float, nullable=True)
    userId = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Define relationship between User and Projections
    user = db.relationship('User', backref=db.backref('projections', lazy=True))

    def __repr__(self) -> str:
        return f'<Projections {self.id}>'

# Function to retrieve the current logged-in user ID
def getCurrentUser():
    if 'userId' in session:
        user_id = session['userId']
        user = User.query.get(user_id)
        if user:
            return user.id  # Return only the user ID
    return None

# Function to hash the password using sha256
def hashPassword(password):
    # Use a specific salt format for PostgreSQL compatibility; use random salt for security
    salt = crypt.mksalt(crypt.METHOD_SHA512)  # Using SHA-512 for stronger security
    hashed = crypt.crypt(password, salt)
    return hashed

# Function to check the password
def checkPassword(hashedPassword, inputPassword):
    # Re-hash the input password with the same salt and compare
    return crypt.crypt(inputPassword, hashedPassword) == hashedPassword

# Function to calculate future value based on inputs
def calculateFutureValue(deposit, monthlyPayment, years, annualAer):
    monthlyAer = (1 + annualAer) ** (1 / 12) - 1 # Calculate monthly Aer from annual rate
    totalMonths = years * 12
    futureDeposit = deposit * (1 + annualAer) ** years
    futureMonthlyPayments = monthlyPayment * (((1 + monthlyAer) ** totalMonths - 1) / monthlyAer)
    return round(futureDeposit + futureMonthlyPayments, 2)

# Function to determine the Aer based on risk tolerance
def getRiskAer(riskTolerance):
    if riskTolerance == 'low':
        return 0.0408
    elif riskTolerance == 'medium':
        return 0.0529
    elif riskTolerance == 'high':
        return 0.1158
    else:
        return 0.0484 # Default value

# Calculate a risk rating count based answers from fact find form
def calculateRiskRatingCount(riskTolerance, investmentComfort, investmentReview):
    riskRatingCount = 0 # Defualt Value
    # Increment count based on risk tolerance
    if riskTolerance == 'high':
        riskRatingCount += 3
    elif riskTolerance == 'medium':
        riskRatingCount += 2
    else:  # 'low'
        riskRatingCount += 1

    # Increment count based on comfort level
    if investmentComfort == 'veryComfortable':
        riskRatingCount += 3
    elif investmentComfort == 'somewhatComfortable':
        riskRatingCount += 2
    else:  # 'notComfortable'
        riskRatingCount += 1

    # Increment count based on investment review frequency
    if investmentReview == 'regularly':
        riskRatingCount += 3
    elif investmentReview == 'occasionally':
        riskRatingCount += 2
    else:  # 'rarely'
        riskRatingCount += 1

    return riskRatingCount

# Function to add initial data to the database (2 admin users + 10 regular users)
def addData():
    try:
        # Check if there are already any users in the database
        if User.query.first() is not None:
            print("Data already initialized.")
            return  # Exit the function early if data exists

        # Create and add the admin users if they do not already exist
        admin_users = [
            {'username': 'admin1', 'password': 'admin_password1'},
            {'username': 'admin2', 'password': 'admin_password2'}
        ]
        regular_users = [
            {'username': f'user{i}', 'password': f'user{i}_password'} for i in range(1, 11)
        ]

        # Add users to the database if they do not already exist
        for user_data in admin_users + regular_users:
            # Check if user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if not existing_user:
                new_user = User(
                    username=user_data['username'],
                    password=hashPassword(user_data['password']),
                    admin=True if 'admin' in user_data['username'] else False
                )
                db.session.add(new_user)

        db.session.commit()  # Commit all users to the database

        # Retrieve all users from the database
        all_users = User.query.all()

        # Define values for projections
        deposit = 1000.0
        monthly_payment = 50.0
        years = 10

        # Add projections with random amounts if they do not already exist
        for user in all_users:
            # Check if a projection already exists for the user
            existing_projection = Projections.query.filter_by(userId=user.id).first()
            if not existing_projection:
                # Use default values for AER and risk rating
                annual_aer = 0.0484  # Default AER
                risk_aer = getRiskAer('medium')  # Calculate AER based on risk rating
                
                # Calculate the future value of savings and risk-adjusted savings
                projection_amount = calculateFutureValue(deposit, monthly_payment, years, annual_aer)
                projection_risk_amount = calculateFutureValue(deposit, monthly_payment, years, risk_aer)
                
                # Create a new projection entry
                projection = Projections(
                    deposit=deposit,
                    monthlyPayment=monthly_payment,
                    years=years,
                    savings=True,
                    highDebt=False,
                    changes=False,
                    riskRating='medium',
                    riskRatingCount=calculateRiskRatingCount('medium', 'veryComfortable', 'regularly'),
                    projectionAmount=projection_amount,
                    projectionRiskAmount=projection_risk_amount,
                    userId=user.id
                )
                db.session.add(projection)

        db.session.commit()  # Commit all projections to the database

    except IntegrityError:
        # Handle database integrity errors (e.g., duplicates)
        db.session.rollback()
        print("Error adding data. Some entries might already exist.")
    except Exception as e:
        # Handle any other unexpected errors
        db.session.rollback()
        print(f"An unexpected error occurred: {e}")

# Default route which is user login
@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and checkPassword(user.password, password):  # Check hashed password
            session['userId'] = user.id
            session['admin'] = user.admin
            return redirect(url_for('home'))
        else:
            return render_template('index.html', error="Invalid credentials")

    return render_template('index.html')

# Route for sign up
@app.route('/signUp', methods=['GET', 'POST'])
def signUp():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate username and password length
        if len(username) < 5 or len(username) > 15:
            flash("Username must be between 5 and 15 characters", 'warning') # (Message Flashing, 2024)
            return redirect(url_for('signUp'))

        if len(password) < 5 or len(password) > 15:
            flash("Password must be between 5 and 15 characters", 'warning')
            return redirect(url_for('signUp'))

        if password != confirm_password:
            flash("Passwords do not match", 'warning')
            return redirect(url_for('signUp'))

        hashedPassword = hashPassword(password)

        new_user = User(username=username, password=hashedPassword, admin=False)
        #(Python Tutorials, 2023)

        try:
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('signUp', success=True))
        except:
            # Warning error if username already exists
            flash("Username already exists", 'warning')
            return redirect(url_for('signUp'))

    return render_template('signUp.html')

# Route for home page- accessible once user has logged in
@app.route('/home', methods=['GET'])
def home():
    user = getCurrentUser()
    if user:
        return render_template('home.html', admin=session.get('admin'), user=user)
    else:
        return redirect(url_for('index'))

# Route for the admin page - admin users can perform CRUD operations on user details
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check if the user is logged in and has admin privileges
    if 'userId' in session and session.get('admin'):
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            # Convert the 'admin' checkbox value to a boolean 
            admin = request.form.get('admin') == 'yes'

            # Validate the username length is between 5 and 15 characters
            if not (5 <= len(username) <= 15):
                # Display an error message if it is not
                flash("Username must be between 5 and 15 characters long", 'danger')
                return render_template('admin.html', users=User.query.all())
            
            # Validate that password length is between 5 and 15 characters
            if not (5 <= len(password) <= 15):
                # Display an error message if it is nott
                flash("Password must be between 5 and 15 characters long", 'danger')
                return render_template('admin.html', users=User.query.all())
            
            # Hash password for security
            hashed_password = hashPassword(password)

            # Create a new User object
            new_user = User(username=username, password=hashed_password, admin=admin)
            
            try: # Commit new User object
                db.session.add(new_user)
                db.session.commit()
                flash("User added successfully", 'success') # Display success message
            except Exception as e:
                # Handle any exceptions
                print(f"Error: {e}")
                flash("Username already exists", 'danger')

        # Retrieve all users from the database to display on the page
        users = User.query.all()
        return render_template('admin.html', users=users)
    else:
        # If the user is not logged in or is not an admin, redirect to the login page
        return redirect(url_for('index'))

@app.route('/userAccount', defaults={'id': None}, methods=['GET', 'POST'])
@app.route('/userAccount/<int:id>', methods=['GET', 'POST'])
def userAccount(id):
    # Get the currently logged-in user ID from the session
    current_user_id = session.get('userId')
    
    if current_user_id:
        if id is None:  # If no specific ID is provided, assume the current user's ID
            id = current_user_id

        # Fetch the user object from the database
        user = User.query.get_or_404(id)

        if request.method == 'POST':
            # Retrieve the new username and password from the form
            new_username = request.form['username']
            new_password = request.form['password']

            # Check if the new username is already in use by another user
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user and existing_user.id != user.id:
                flash("Username is already in use. Please choose a different one.", 'warning')
            else:
                # Update user details if the username is available
                if new_username:
                    user.username = new_username
                if new_password:
                    user.password = hashPassword(new_password)

                db.session.commit()
                flash("Account updated successfully!", 'success')
                return redirect(url_for('userAccount', id=user.id))

        return render_template('userAccount.html', user=user)

    else:
        return redirect(url_for('index'))
    # (TRCCompSci, 2019)

# Route for admin deleting user from User table
@app.route('/delete/<int:id>')
def delete(id):
    # id of chosen user is passed through and retrieved
    user_to_delete = User.query.get_or_404(id) 
    try:
        # Deletes user
        Projections.query.filter_by(userId=id).delete()
        db.session.delete(user_to_delete)
        db.session.commit()
        
        return redirect(url_for('admin'))
    
    # Handles exception
    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()  
        return 'Error with deleting user'

# Route for admin updating user details (similar to userAccount route)
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    user = User.query.get_or_404(id)

    if request.method == 'POST':
        # Retrieve the new username and password
        new_username = request.form['username']
        new_password = request.form['password']

        # Validate username and password length
        if not (5 <= len(new_username) <= 15):
            flash("Username must be between 5 and 15 characters", 'warning')
        if new_password and not (5 <= len(new_password) <= 15):
            flash("Password must be between 5 and 15 characters", 'warning')
     
        # Check if the new username is already in use
        if User.query.filter_by(username=new_username).first() and new_username != user.username:
            flash("Username already exists", 'warning')

        # Generates hash of password to ensure security
        user.username = new_username
        if new_password:
            user.password = hashPassword(new_password)

        # Updates user details if username is available
        db.session.commit()
        flash("Account updated successfully", 'success')

    return render_template('update.html', user=user)

# Route for user to log out of application
@app.route('/logout')
def logout():
    session.pop('userId', None)
    session.pop('admin', None)
    # Redirects to log in page
    return redirect(url_for('index'))

# Route for fact find where users complete form for projections
@app.route('/factFind/', methods=['GET', 'POST'])
def factFind():
    user = getCurrentUser()  # Get the current user
    if not user:
        # Redirect to the login page if no user is authenticated
        return redirect(url_for('index')) 

    if request.method == 'POST':
        try:
            # Retrieve all form data from the request
            deposit = request.form.get('deposit')
            monthlyPayment = request.form.get('monthlyPayment')
            years = request.form.get('years')
            savings = request.form.get('savings')
            highDebt = request.form.get('highDebt')
            changes = request.form.get('changes')
            riskTolerance = request.form.get('riskTolerance')
            investmentComfort = request.form.get('investmentComfort')
            investmentReview = request.form.get('investmentReview')

            # Ensure that all fields have been filled out
            if not all([deposit, monthlyPayment, years, savings, highDebt, changes, riskTolerance, investmentComfort, investmentReview]):
                return render_template('factFind.html', error="All fields must be filled out")

            # Convert to requested data types matching table layout
            deposit = float(deposit)
            monthlyPayment = float(monthlyPayment)
            years = int(years)
            savings = savings == 'true'
            highDebt = highDebt == 'true'
            changes = changes == 'true'

            # Calculate the attitude to risk score count
            riskRatingCount = calculateRiskRatingCount(riskTolerance, investmentComfort, investmentReview)

            userId = session['userId']

            # Checks if there is an existing projection for current user
            eligibility = Projections.query.filter_by(userId=userId).first()
            if eligibility: # Updates existing projection if True
                eligibility.deposit = deposit
                eligibility.monthlyPayment = monthlyPayment
                eligibility.years = years
                eligibility.savings = savings
                eligibility.highDebt = highDebt
                eligibility.changes = changes
                eligibility.riskRating = riskTolerance
                eligibility.riskRatingCount = riskRatingCount
            else: # If not, creates a new one
                eligibility = Projections(
                    deposit=deposit,
                    monthlyPayment=monthlyPayment,
                    years=years,
                    savings=savings,
                    highDebt=highDebt,
                    changes=changes,
                    riskRating=riskTolerance,
                    riskRatingCount=riskRatingCount,
                    userId=userId
                )
                db.session.add(eligibility)

            # Calculate future values for projections
            annualAer = 0.0484  # Default annual AER
            futureValue = calculateFutureValue(deposit, monthlyPayment, years, annualAer)
            riskAer = getRiskAer(riskTolerance)  # Get AER based on the user's risk attitude
            futureValueRisk = calculateFutureValue(deposit, monthlyPayment, years, riskAer)

            # Update projection amounts in the eligibility record
            eligibility.projectionAmount = futureValue
            eligibility.projectionRiskAmount = futureValueRisk
            db.session.commit()

            # Debugging: confirm successful data saving
            print("Data and projections saved successfully to the database.")

            return redirect(url_for('projection'))

        # Handle any errors 
        except Exception as e:
            print(f"Error: {e}")
            return render_template('factFind.html', error="An error occurred while saving your data.")
    return render_template('factFind.html')

# Route for projection which displays projection amount after fact find form completed
@app.route('/projection')
def projection():
    # Displays projection for current user
    userId = getCurrentUser()
    if userId:
        projection = Projections.query.filter_by(userId=userId).first()
        if projection:
            return render_template(
                'projection.html',
                deposit=projection.deposit,
                monthlyPayment=projection.monthlyPayment,
                years=projection.years,
                projectionAmount=projection.projectionAmount,
                projectionRiskAmount=projection.projectionRiskAmount,
                riskRating=projection.riskRating
            )
    return render_template('projection.html', error="Projection data not available")

# Route for recommendations which displays recent projection for current user
@app.route('/recommendations')
def recommendations():
    user = getCurrentUser()
    if user:
        userId = session['userId']

        # Fetch all Projections for the current user
        projectionsData = Projections.query.filter_by(userId=userId).all()

        # Pass data to the template
        return render_template('recommendations.html', projectionsData=projectionsData)
    else:
        return redirect(url_for('index'))

# Entry point for the application
if __name__ == '__main__':
    #addData()  # Initialize data once when the app starts
    app.run()

#(Jakerieger, 2022)


